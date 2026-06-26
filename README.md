# bash-destructive-guard

Pi extension that denies `bash` tool calls invoking destructive verbs (`rm`, `mv`) against paths outside a configurable safe list. Companion to `secrets-guard` — together they bracket the two highest-frequency catastrophic outcomes (data destruction and credential exfiltration).

## Hooked events

- **`tool_call` for `bash`** — preprocesses, runs a quote-aware lexer, and applies layered per-segment checks.

## Threat model

This guard provides **blast-radius isolation** against the agent issuing a *naive or mistaken* destructive command (`rm /etc/foo`, `rm;rm /x`, `sudo rm`, `find . -exec rm`, a pasted one-liner). It is **not** a sandbox and **not** a defense against an adversary deliberately crafting shell to evade it — static analysis of shell is undecidable, so ANSI-C quoting (`$'\x72m'`), parameter-default expansion (`${x:-rm}`), variable indirection (`R=rm; $R /x`), and `eval`-of-substitution are accepted fail-open residual gaps (documented in `index.ts`). Anyone with shell and intent can also set `SKIP_DESTRUCTIVE_GUARD=1`.

## Detection model (#297)

**Preprocess:** collapse `\<newline>` line continuations, strip heredoc bodies (their content is data, not commands), normalize `$IFS`/`${IFS}` to a space.

**Quote-aware lexer:** split into command-position *segments* on **unquoted** control operators and group/subshell/substitution boundaries (`;`, `|`, `&`, `(`, `)`, newline, backtick); strip surrounding quotes and escaping backslashes from each token; record whether a segment reads a script from stdin/a file (`<`, `<<`, `<<<`). Leading `NAME=value` env assignments — including quoted multi-word values — are dropped so the real verb surfaces. The verb is basename-normalized (`/bin/rm` → `rm`).

**Per segment (in order):**

1. **Shell interpreter with `-c` OR reading a script from stdin/file** (`bash -c '...'`, `bash<<<'...'`, `bash <<EOF`) → **DENY** (bypass vector).
2. **Exec-wrapper verb** (`eval`, `xargs`, `sudo`, `su`, `env`, `nohup`, `command`, `timeout`, `find`, `exec`, …) whose tokens carry `rm`/`mv` as a standalone word → **DENY** (the wrapped target is not statically validatable; word-level so a path component named `rm` does not overblock).
3. **Plain `rm` or `mv`** — extract path arguments (skipping flags, honoring `--`), then for each path token:
   - Path containing shell metacharacters (`$`, `` ` ``, `|`, `;`, `&`, `(`, `)`, `{`, `}`) → **DENY**
   - Path containing `..` traversal segment → **DENY**
   - Absolute path not under any safe path → **DENY**
   - Relative path (not starting with `/`) → **ALLOW** (implicitly within `cwd`)
4. **Any other verb** → **ALLOW**.

Because `$(...)`/backtick/subshell bodies become their own segments, a destructive verb inside them is path-validated directly (safe paths allowed, unsafe blocked) rather than blunt-blocked — so a compound like `echo $(rm /tmp/scratch)` is allowed while `echo $(rm /etc/x)` is denied.

## Safe paths

Built-in: `/tmp`, the active pi `cwd` (and everything beneath it).

User-extendable via `~/.config/pi/bash-guard-safe-paths.conf`:

```text
# One path per line. Blank lines and # comments ignored.
# Paths are matched by exact equality or as a prefix with trailing /.
/var/tmp
/home/me/sandbox
/srv/scratch
```

The `cwd` entry means the extension does not block destructive operations within the project pi is operating on. That is intentional — destructive operations within the project (e.g. `rm node_modules`) are part of normal workflow and the project's own VCS is the recovery mechanism.

## Refusal policy (per-rule)

The `damage-control-continue` pattern (from `disler/pi-vs-claude-code`, evaluated in #69) distinguishes **hard refusals** — where any retry is wrong and the agent should escalate to the user — from **continue-eligible** blocks, where the agent can recover by trying a modified approach. This extension classifies its rules accordingly; `reason:` payloads carry explicit guidance:

| Rule | Policy | Rationale |
|---|---|---|
| Shell interpreter with `-c` / stdin script (rule 1) | **Hard refusal** | The bypass intent itself is what is blocked, not the wrapped command. Re-wrapping the same payload is never the right retry. `reason:` instructs the model to invoke the verb directly instead. |
| Exec-wrapper carrying `rm`/`mv` (rule 2) | Continue-eligible | The agent can invoke the destructive command directly so its path can be validated, scope it under `/tmp`/cwd, or set the override. |
| `rm`/`mv` path with shell metacharacters (rule 3a) | Continue-eligible | The agent can expand the glob/variable and issue the verb with literal paths. |
| `rm`/`mv` path with `..` traversal (rule 3b) | Continue-eligible | The agent can resolve to an absolute path or drop the `..` segments. |
| `rm`/`mv` absolute path outside safe list (rule 3c) | Continue-eligible | The agent can switch to a cwd-relative path, edit `~/.config/pi/bash-guard-safe-paths.conf`, or operate under `/tmp`. |

Neither the upstream `damage-control.ts` nor `damage-control-continue.ts` were vendored. The pattern adoption is pi-native: pi's `{block, reason}` return is already the no-abort path (this extension has never called `ctx.abort()`), so the actionable change is the per-rule policy classification and adaptive-feedback wording in `reason:` payloads.

## Override

The override **announces itself via `ctx.ui.notify`** on use — silent overrides are not supported (ADR-0022 § Q5, backported per issue #258).

| Override | Scope |
|---|---|
| `SKIP_DESTRUCTIVE_GUARD=1` in pi's env | Whole pi session — extension loads but installs no `tool_call` handler; announced once at session start via `warning`-level notify |

In non-UI sessions (e.g. `pi -p`) the notify call is suppressed cleanly via the `ctx.hasUI` guard.

There is no per-call override. If you need to delete something outside the safe list and outside `cwd`, either run the command directly in a separate terminal or extend `bash-guard-safe-paths.conf` first.

## Why not also block `dd`, `mkfs`, `chmod -R 777 /`?

The framework's earlier iteration extended this set; in practice, model-driven invocations of these are vanishingly rare and the false-positive cost is high (e.g. `chmod` on legitimate project files). `rm` and `mv` cover ~99% of the realized destructive-action risk. New verbs can be added to `DESTRUCTIVE_VERBS` if needed.

## Limitations

- The lexer is quote-aware (single/double quotes, backslash escapes, env assignments, `$IFS`) but is **not** a full POSIX shell parser. Runtime-expansion evasions (ANSI-C `$'...'`, `${x:-rm}`, variable indirection, `eval`-of-substitution) are documented fail-open residual gaps per the threat model above — they are adversarial, not accidental.
- Quote-unaware *data* containing a destructive verb plus an absolute path inside a non-shell command is handled correctly (e.g. `echo "; rm /etc/x"` is allowed — the `;` is inside quotes), but a benign command whose **arguments** name `rm`/`mv` as a standalone word under an exec-wrapper (e.g. `sudo grep rm file`) is conservatively denied (fail-closed).
- Out of scope entirely (different verbs, not `rm`/`mv`): `>` redirect-clobber, `find -delete`, `truncate`, `dd of=`, `python -c 'os.remove(...)'`.
- The extension does not distinguish `rm -rf` from `rm` of a single file. The path-list check is what gates the action.
