# bash-destructive-guard

Pi extension that denies `bash` tool calls invoking destructive operations against paths outside a configurable safe list — `rm`/`mv`, output-redirect clobber (`>`/`>|`), `find -delete`, `dd of=`, and `truncate` (ADR-0072). Companion to `secrets-guard` — together they bracket the two highest-frequency catastrophic outcomes (data destruction and credential exfiltration). The quote-aware lexer lives in [`../shared/shell-lex.ts`](https://github.com/psmfd/pi-config/blob/main/agent/extensions/shared/README.md); this extension owns the destructive-operation policy.

## Install

```sh
pi install git:github.com/psmfd/pi-bash-destructive-guard
```

Try it first without installing: `pi -e git:github.com/psmfd/pi-bash-destructive-guard`.

## Hooked events

- **`tool_call` for `bash`** — preprocesses, runs a quote-aware lexer, and applies layered per-segment checks.

## Threat model

This guard provides **blast-radius isolation** against the agent issuing a *naive or mistaken* destructive command (`rm /etc/foo`, `rm;rm /x`, `sudo rm`, `find . -exec rm`, `echo <b64> | base64 -d | sh`, a pasted one-liner). It is **not** a sandbox and **not** a defense against an adversary deliberately crafting shell to evade it — static analysis of shell is undecidable, so ANSI-C quoting (`$'\x72m'`), parameter-default expansion (`${x:-rm}`), variable indirection (`R=rm; $R /x`), a value-producing substitution (`$(echo rm) -rf /`), and base64-decode pipelines are accepted fail-open residual gaps (documented in `index.ts`). It also **cannot** see a destructive verb that only appears in a file a second interpreter reads — the GuardFall Makefile-exfil class, where the string this guard receives is merely `make test`. The sound boundary is below the shell (`$HOME` scoping / sandbox / egress control, #507); the AST-parser hardening is #506. Anyone with shell and intent can also set `SKIP_DESTRUCTIVE_GUARD=1`.

## Detection model (#297, extended by ADR-0072)

**Preprocess** (`../shared/shell-lex.ts`): collapse `\<newline>` line continuations, strip heredoc bodies (their content is data, not commands), normalize `$IFS`/`${IFS}` to a space (word-boundary anchored, so `$IFSX` is left intact).

**Two-variant analysis:** the checks run over both the preprocessed command **and** a *deglued* variant with word-internal empty command substitutions removed (`r$(true)m` → `rm`); a rule tripping in either variant blocks. This closes the glued empty-substitution obfuscation conservatively while leaving space-separated value substitutions (`rm $(echo /tmp)/x`) untouched (no path-arg false positives).

**Quote-aware lexer:** split each variant into command-position *segments* on **unquoted** control operators and group/subshell/substitution boundaries (`;`, `|`, `&`, `(`, `)`, newline, backtick); strip surrounding quotes and escaping backslashes from each token; record whether a segment reads a script from stdin/a file (`<`, `<<`, `<<<`), is the downstream stage of a single `|` pipe, and any output redirections (`>`, `>|`, `>>`) with their targets. `||` (logical-OR) is distinguished from a `|` pipe. Leading `NAME=value` env assignments — including quoted multi-word values — are dropped so the real verb surfaces. The verb is basename-normalized (`/bin/rm` → `rm`).

**Per segment (in order):**

0. **Output-redirect clobber** (`>`, `>|`) to a path outside the safe list → **DENY** (`>>` append is out of scope).
1. **Shell interpreter with `-c`, reading a script from stdin/file, OR as a `|` pipeline sink** (`bash -c '...'`, `bash<<<'...'`, `bash <<EOF`, `… | sh`) → **DENY** (bypass vector).
2. **Exec-wrapper verb** (`eval`, `xargs`, `sudo`, `su`, `env`, `nohup`, `command`, `timeout`, `find`, `exec`, …) whose tokens carry `rm`/`mv` as a standalone word → **DENY** (the wrapped target is not statically validatable; word-level so a path component named `rm` does not overblock).
3. **Plain `rm` or `mv`** — extract path arguments (skipping flags, honoring `--`), then for each path token:
   - Path containing shell metacharacters (`$`, `` ` ``, `|`, `;`, `&`, `(`, `)`, `{`, `}`) → **DENY**
   - Path containing `..` traversal segment → **DENY**
   - Absolute path not under any safe path → **DENY**
   - Relative path (not starting with `/`) → **ALLOW** (implicitly within `cwd`)
4. **`find … -delete`** rooted at an unsafe leading path → **DENY** (a safe/relative/absent root is allowed, consistent with `rm`).
5. **`dd of=<target>`** — a `/dev/*` device target → **DENY** unconditionally; any other `of=` target is path-checked like `rm`.
6. **`truncate -s <n> <path>`** — path-checked like `rm` (the `-s`/`--size` value is skipped).
7. **Any other verb** → **ALLOW**.

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
| Output-redirect clobber to unsafe path (rule 0) | Continue-eligible | The agent can redirect to a cwd-relative or `/tmp` path, or `>>`-append if overwrite was not intended. |
| Shell interpreter with `-c` / stdin script / pipe sink (rule 1) | **Hard refusal** | The bypass intent itself is what is blocked, not the wrapped command. Re-wrapping or re-piping the same payload is never the right retry. `reason:` instructs the model to invoke the verb directly instead. |
| Exec-wrapper carrying `rm`/`mv` (rule 2) | Continue-eligible | The agent can invoke the destructive command directly so its path can be validated, scope it under `/tmp`/cwd, or set the override. |
| `rm`/`mv` path with shell metacharacters (rule 3a) | Continue-eligible | The agent can expand the glob/variable and issue the verb with literal paths. |
| `rm`/`mv` path with `..` traversal (rule 3b) | Continue-eligible | The agent can resolve to an absolute path or drop the `..` segments. |
| `rm`/`mv` absolute path outside safe list (rule 3c) | Continue-eligible | The agent can switch to a cwd-relative path, edit `~/.config/pi/bash-guard-safe-paths.conf`, or operate under `/tmp`. |
| `find -delete` / `dd of=` / `truncate` on unsafe target (rules 4–6) | Continue-eligible | Same recovery as `rm`/`mv`: scope the target under cwd/`/tmp`, extend the safe-paths file, or set the override. `dd` to a `/dev/*` device is not path-recoverable — use a regular file. |

Neither the upstream `damage-control.ts` nor `damage-control-continue.ts` were vendored. The pattern adoption is pi-native: pi's `{block, reason}` return is already the no-abort path (this extension has never called `ctx.abort()`), so the actionable change is the per-rule policy classification and adaptive-feedback wording in `reason:` payloads.

## Override

The override **announces itself via `ctx.ui.notify`** on use — silent overrides are not supported (ADR-0022 § Q5, backported per issue #258).

| Override | Scope |
|---|---|
| `SKIP_DESTRUCTIVE_GUARD=1` in pi's env | Whole pi session — extension loads but installs no `tool_call` handler; announced once at session start via `warning`-level notify |

In non-UI sessions (e.g. `pi -p`) the notify call is suppressed cleanly via the `ctx.hasUI` guard.

There is no per-call override. If you need to delete something outside the safe list and outside `cwd`, either run the command directly in a separate terminal or extend `bash-guard-safe-paths.conf` first.

## Why not also block `mkfs`, `chmod -R 777 /`, `shred`, `git push --force`?

ADR-0072 added the highest-incident destructive operations beyond `rm`/`mv` (`>`/`>|` clobber, `find -delete`, `dd of=`, `truncate`). The still-deferred set — `shred`, `wipefs`, `mkfs.*`, `parted`/`sgdisk`, and out-of-domain blast-radius verbs like `git clean -fdx` / `git reset --hard` / `git push --force` — is enumerated in ADR-0072 § Q4 as a later decision: either low model-invocation frequency with high false-positive cost (e.g. `chmod` on legitimate project files) or a different domain that warrants its own rule. New verbs slot into the per-segment dispatch in `index.ts`.

## Limitations

- The lexer (`../shared/shell-lex.ts`) is quote-aware (single/double quotes, backslash escapes, env assignments, `$IFS`) but is **not** a full POSIX shell parser. Runtime-expansion evasions (ANSI-C `$'...'`, `${x:-rm}`, variable indirection, value-producing/non-glued substitution, base64-decode pipelines) are documented fail-open residual gaps per the threat model above — they are adversarial, not accidental. The glued **empty** substitution (`r$(true)m`) is caught conservatively; the structural fix for the general case is the AST-parser follow-up (#506).
- Quote-unaware *data* containing a destructive verb plus an absolute path inside a non-shell command is handled correctly (e.g. `echo "; rm /etc/x"` is allowed — the `;` is inside quotes), but a benign command whose **arguments** name `rm`/`mv` as a standalone word under an exec-wrapper (e.g. `sudo grep rm file`) is conservatively denied (fail-closed).
- **File-content indirection is invisible.** A destructive verb that lives in a `Makefile`/`package.json` script the agent runs via `make test`/`npm run` never appears in the command string, so no lexer improvement catches it — this needs the OS-level control in #507.
- Out of scope entirely (different verbs): `>>` append-redirect, `python -c 'os.remove(...)'`, `mkfs`/`shred`/`wipefs` (ADR-0072 § Q4 deferred set).
- The extension does not distinguish `rm -rf` from `rm` of a single file. The path-list check is what gates the action.
