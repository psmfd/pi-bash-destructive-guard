/**
 * bash-destructive-guard — pi extension
 *
 * Denies bash tool calls that invoke destructive operations against paths
 * outside a configurable safe list. Runs as a pi extension hooked on the
 * `tool_call` event for `bash`. The quote-aware lexing primitive lives in
 * agent/extensions/shared/shell-lex.ts (ADR-0072) so sibling guards can reuse
 * it; this file owns POLICY (which verbs/flags/paths are destructive).
 *
 * THREAT MODEL (read this before "fixing" a bypass):
 *   This guard provides BLAST-RADIUS ISOLATION against the agent issuing a
 *   *naive or mistaken* destructive command — `rm /etc/foo`, `rm;rm /x`,
 *   `sudo rm`, `eval 'rm ...'`, `echo <b64> | base64 -d | sh`, a pasted
 *   one-liner, etc. It is NOT a sandbox and NOT a defense against an adversary
 *   who is deliberately crafting shell to evade it: anyone with bash and intent
 *   can use ANSI-C quoting (`$'\x72m'`), parameter-default expansion
 *   (`${x:-rm}`), variable indirection (`R=rm; $R /x`), a value-producing
 *   substitution (`$(echo rm) -rf /`), a base64 payload only decoded at
 *   runtime, or simply set SKIP_DESTRUCTIVE_GUARD=1. It also CANNOT see a
 *   destructive verb that lives in a file a second interpreter reads — the
 *   GuardFall Makefile-exfil class (`make test` runs a recipe containing
 *   `rm -rf ~/.aws`): the string this guard receives is only `make test`.
 *   Static analysis of shell is undecidable; we catch the realistic accidental
 *   cases and document the rest. The sound boundary is below the shell
 *   (execve/sandbox + $HOME scoping + egress control, issue #507). See
 *   ADR-0072 and "Residual gaps" below.
 *
 * Safe paths:
 *   - Built-in: /tmp, the current pi cwd (and anything beneath it)
 *   - User-extendable via ~/.config/pi/bash-guard-safe-paths.conf
 *     (one path per line, blank lines and # comments ignored)
 *
 * Override:
 *   - SKIP_DESTRUCTIVE_GUARD=1 in pi's env (extension loads but no hook)
 *
 * Detection model (#297, extended by ADR-0072):
 *   Preprocess (shared/shell-lex.ts): collapse `\<newline>` line continuations,
 *   strip heredoc bodies, normalize `$IFS`/`${IFS}` to a space. Analysis runs
 *   over TWO command variants — the preprocessed command and a "deglued"
 *   variant with word-internal empty command substitutions removed
 *   (`r$(true)m` → `rm`); a rule tripping in EITHER variant blocks. Each variant
 *   is lexed into command-position segments; per segment:
 *     0. Output redirection (`>`, `>|`) to an unsafe path  → DENY (clobber)
 *     1. Shell-interpreter verb (bash/sh/...) with `-c`, reading a script from
 *        stdin/file (`<`/`<<`/`<<<`), OR as a `|` pipeline sink → DENY (bypass)
 *     2. Exec-wrapper verb (eval/xargs/sudo/find/...) whose token list contains
 *        a destructive operation — rm/mv/dd/truncate (basename-normalized),
 *        `find -delete`, or a quote-embedded `>` clobber                → DENY
 *     3. `rm`/`mv` targeting an unsafe path                 → DENY
 *     4. `find ... -delete` rooted at an unsafe path        → DENY
 *     5. `dd of=<device|unsafe path>`                       → DENY
 *     6. `truncate -s <n> <unsafe path>`                    → DENY
 *     7. Anything else                                      → allow
 *
 * AST second pass (#506, ADR-0100 — see ast-second-pass.ts): when a command
 * uses substitution or ANSI-C quoting, the vendored pi-bash-parser binary
 * provides a real parse and the SAME policy is re-applied to it, closing the
 * hand-lexer's gaps for ANSI-C-quoted verbs/flags (`$'\x72m' /x`) and
 * destructive verbs in nested command substitution as their own command
 * positions. Additive: it only ADDS a denial (binary present + parse ok +
 * policy hit); binary-absent / parse-failure fall back to this hand-lexer
 * unless PI_BASH_GUARD_AST_STRICT=1.
 *
 * Residual gaps (fail-open by design; adversarial, not accidental) — NOT closed
 * by the AST pass because no single-command-string parser can resolve them:
 *   - parameter-default expansion: `${x:-rm} /x`
 *   - variable indirection: `R=rm; $R /x`
 *   - value-producing substitution: `$(echo rm) -rf /` (the value only exists
 *     at runtime; the parser renders it empty, the glued EMPTY case
 *     `r$(true)m` IS caught)
 *   - base64/decode pipelines whose payload only exists after execution
 *   - file-content indirection: `make test` where the Makefile recipe deletes
 *   These require runtime expansion / execution the guard does not perform, or
 *   a control below the shell (#507 OS sandbox). Out of scope entirely
 *   (different verbs): `>>` append, `python -c 'os.remove(...)'`.
 *
 * Source rule: this extension is the runtime counterpart to
 * agent/rules/secrets-guard.md's "blast-radius isolation" principle.
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { astSecondPass, initAstConfig } from "./ast-second-pass.ts";
import { canonicalize } from "./paths.ts";
import { SHELL_INTERPRETERS, WRAPPER_VERBS } from "./policy-verbs.ts";
import {
  analyzeReportOnlySegment,
  isReportOnlyProfileActive,
  sanitizeGeneralDenyForProfile,
} from "./report-only.ts";
import {
  lex,
  preprocessCommand,
  deglueWordSubstitutions,
  stripEnvAssignments,
  hasMinusC,
  type Segment,
  type Redirect,
} from "./shared/shell-lex.ts";

// Verb classification sets shared with the report-only profile (ADR-0091)
// live in policy-verbs.ts. The general guard's wrapper handling fails closed
// when a wrapper's token list contains rm|mv as a standalone word.
const DESTRUCTIVE_VERBS = new Set(["rm", "mv"]);
const META_CHAR_RE = /[$`|;&(){}]/;

function loadUserSafePaths(): string[] {
  const file = join(homedir(), ".config", "pi", "bash-guard-safe-paths.conf");
  if (!existsSync(file)) return [];
  try {
    return readFileSync(file, "utf8")
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith("#"));
  } catch {
    return [];
  }
}

// Destructive verbs that cannot be statically validated once wrapped, so the
// whole wrapped invocation is refused. Mirrors the direct-invocation surface
// (rules 3/5/6) — a verb added there must be added here too, or the wrapper
// path silently re-opens the bypass (#798, ADR-0112).
const WRAPPED_DESTRUCTIVE_WORDS = new Set(["rm", "mv", "dd", "truncate"]);

// True if a wrapper's argument tokens carry a destructive operation. Word-level
// (not token-exact) so a wrapped command string carried in one quoted token
// (`eval 'rm /x'`, `su -c 'rm /x'`) is detected, while a path component named
// rm/mv (`/home/rm/file`) is not. Each word is basename-normalized so a wrapped
// absolute path (`sudo /bin/rm`) classifies like its basename, matching how the
// segment's own leading verb is normalized (#798, ADR-0112). Three surfaces:
//   - a WRAPPED_DESTRUCTIVE_WORDS verb (rm/mv/dd/truncate);
//   - a quoted `>` clobber — a redirect inside a wrapper payload never surfaces
//     as a structural Redirect (`eval 'echo x > /etc/passwd'`), so checkClobber
//     cannot see it; only unquoted redirects reach seg.redirects;
//   - `find` co-occurring with `-delete` (wrapped `find` is not the segment
//     verb, so rule 4 never runs).
function wrapsDestructive(tokens: string[]): boolean {
  let sawFind = false;
  let sawDelete = false;
  for (const t of tokens.slice(1)) {
    if (t.includes(">")) return true;
    for (const w of t.split(/\s+/)) {
      const base = w.split("/").pop() || w;
      if (WRAPPED_DESTRUCTIVE_WORDS.has(base)) return true;
      if (base === "find") sawFind = true;
      if (w === "-delete") sawDelete = true;
    }
  }
  return sawFind && sawDelete;
}

function isUnderSafePath(target: string, safePaths: string[]): boolean {
  const canon = canonicalize(target);
  for (const sp of safePaths) {
    if (canon === sp) return true;
    if (canon.startsWith(sp.endsWith("/") ? sp : sp + "/")) return true;
  }
  return false;
}

// Single-path safety verdict shared by every destructive operation. Returns a
// block reason if `p` is unsafe (shell metachars, `..` traversal, or an
// absolute path outside the safe list), else null. Relative paths are
// implicitly within cwd and therefore safe.
function pathUnsafeReason(
  p: string,
  safePaths: string[],
  label: string,
): string | null {
  if (META_CHAR_RE.test(p)) {
    return `bash-destructive-guard: ${label} path '${p}' contains shell metacharacters — refusing for safety.

Suggested alternatives:
  - Expand the glob or variable yourself and re-issue with an explicit literal path.
  - Confirm the target list with \`ls <pattern>\` first, then act on each path individually.`;
  }
  if (p.includes("..")) {
    return `bash-destructive-guard: ${label} path '${p}' contains '..' traversal — refusing for safety.

Suggested alternatives:
  - Resolve the path to its absolute form and re-issue with the absolute path.
  - If the intent was relative to cwd, drop the \`..\` segments and use the direct relative path.`;
  }
  // A leading `~` is NOT relative to cwd — bash expands it to the user's home
  // directory, which is outside cwd and usually off the safe list. Resolve it
  // and safe-check the absolute target; reject `~user/…` forms, which cannot be
  // resolved statically (#798, ADR-0112). Without this, `rm ~/.ssh/id_rsa` and
  // `dd of=~/.aws/credentials` fell through the relative-path exemption below.
  if (p.startsWith("~")) {
    if (p === "~" || p.startsWith("~/")) {
      const resolved = p === "~" ? homedir() : join(homedir(), p.slice(2));
      if (!isUnderSafePath(resolved, safePaths)) {
        return `bash-destructive-guard: ${label} '${p}' (→ '${resolved}') — home-directory path outside safe list (${safePaths.join(", ")}).

Suggested alternatives:
  - If the target is genuinely under home, add its parent to \`~/.config/pi/bash-guard-safe-paths.conf\` (one path per line) and retry.
  - If you only need a scratch location, work under \`/tmp\` — already in the safe list.
  - Last resort for a one-off destructive operation: set \`SKIP_DESTRUCTIVE_GUARD=1\` in the pi session env.`;
      }
      return null;
    }
    return `bash-destructive-guard: ${label} path '${p}' uses a \`~user\` home reference that cannot be resolved statically — refusing for safety.

Suggested alternatives:
  - Re-issue with the resolved absolute path so it can be checked against the safe list.`;
  }
  if (!p.startsWith("/")) return null; // relative → within cwd → safe
  if (!isUnderSafePath(p, safePaths)) {
    return `bash-destructive-guard: ${label} '${p}' — path outside safe list (${safePaths.join(", ")}).

Suggested alternatives:
  - If the operation belongs inside the project, use a path relative to cwd instead of an absolute path.
  - If it is legitimately outside the project, add the parent directory to \`~/.config/pi/bash-guard-safe-paths.conf\` (one path per line) and retry.
  - If you only need a scratch location, work under \`/tmp\` — already in the safe list.
  - Last resort for a one-off destructive operation: set \`SKIP_DESTRUCTIVE_GUARD=1\` in the pi session env.`;
  }
  return null;
}

// Extract positional path arguments from `rm`/`mv` (skip flags, honor `--`).
function destructivePathTokens(tokens: string[]): string[] {
  const paths: string[] = [];
  let pastDashDash = false;
  for (const t of tokens.slice(1)) {
    if (t === "--") {
      pastDashDash = true;
      continue;
    }
    if (pastDashDash || !t.startsWith("-")) paths.push(t);
  }
  return paths;
}

// Leading path operands before the first expression primary (used by `find`,
// whose paths precede the expression: `find <path>... -delete`). GNU find
// accepts global options BEFORE the paths — -H/-L/-P (symlink handling),
// -D <debugopts>, -O<level> — which must be skipped, not treated as the first
// `-flag`. Otherwise `find -L /etc -delete` breaks on -L, yields an empty root
// list, and is misclassified as "no root → cwd → safe" (#798, ADR-0112).
function leadingPathArgs(tokens: string[]): string[] {
  const paths: string[] = [];
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === "-H" || t === "-L" || t === "-P") continue;
    if (t === "-D") {
      i++; // consume the debug-options value
      continue;
    }
    if (/^-O[0-9]?$/.test(t)) continue; // -O, -O1, -O2, -O3
    if (t.startsWith("-")) break; // first expression primary (-delete, -name, …)
    paths.push(t);
  }
  return paths;
}

// Rule 3 — rm/mv path safety.
function checkDestructivePaths(verb: string, tokens: string[], safePaths: string[]): string | null {
  const paths = destructivePathTokens(tokens);
  if (paths.length === 0) return null; // flags-only — harmless
  for (const p of paths) {
    const reason = pathUnsafeReason(p, safePaths, `'${verb}'`);
    if (reason) return reason;
  }
  return null;
}

// Rule 0 — output-redirection clobber (`>`, `>|`) to an unsafe path.
function checkClobber(redirects: Redirect[], safePaths: string[]): string | null {
  for (const r of redirects) {
    if (r.op !== ">" && r.op !== ">|") continue; // `>>` append is out of scope
    if (!r.target) continue;
    const reason = pathUnsafeReason(r.target, safePaths, "output-redirect (>)");
    if (reason) return reason;
  }
  return null;
}

// Rule 4 — `find ... -delete` rooted at an unsafe path.
function checkFindDelete(tokens: string[], safePaths: string[]): string | null {
  if (!tokens.includes("-delete")) return null;
  const roots = leadingPathArgs(tokens);
  // No explicit root → find defaults to cwd, which is inside the safe list.
  for (const p of roots) {
    const reason = pathUnsafeReason(p, safePaths, "'find -delete' root");
    if (reason) return reason;
  }
  return null;
}

// Rule 5 — `dd of=<device|unsafe path>`.
function checkDd(tokens: string[], safePaths: string[]): string | null {
  for (const t of tokens.slice(1)) {
    if (!t.startsWith("of=")) continue;
    const target = t.slice(3);
    if (!target) continue;
    if (target.startsWith("/dev/")) {
      return `bash-destructive-guard: 'dd of=${target}' writes directly to a device — refusing for safety.

Suggested alternatives:
  - Write to a regular file under cwd or \`/tmp\` instead of a device node.
  - If writing to a device is genuinely intended, run it in a separate terminal or set \`SKIP_DESTRUCTIVE_GUARD=1\` for a one-off.`;
    }
    const reason = pathUnsafeReason(target, safePaths, "'dd of='");
    if (reason) return reason;
  }
  return null;
}

// Rule 6 — `truncate -s <n> <unsafe path>`. Skips the size flag/value, then
// path-checks the remaining operands.
function checkTruncate(tokens: string[], safePaths: string[]): string | null {
  const paths: string[] = [];
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === "-s" || t === "--size") {
      i++; // consume the size value
      continue;
    }
    if (t.startsWith("-")) continue; // -s0, --size=0, other flags
    paths.push(t);
  }
  for (const p of paths) {
    const reason = pathUnsafeReason(p, safePaths, "'truncate'");
    if (reason) return reason;
  }
  return null;
}

// Per-segment policy. Returns a block reason or null.
function analyzeSegment(seg: Segment, safePaths: string[]): string | null {
  // Rule 0 — clobber can apply even with no command tokens (`> /etc/passwd`).
  const clobber = checkClobber(seg.redirects, safePaths);
  if (clobber) return clobber;

  const tokens = stripEnvAssignments(seg.tokens);
  if (tokens.length === 0) return null;
  // Basename-normalize the verb so an absolute/relative path to the binary
  // (`/bin/rm`, `/usr/bin/sudo`) classifies like its basename.
  const rawVerb = tokens[0];
  const verb = rawVerb.split("/").pop() || rawVerb;

  // Rule 1 — shell interpreter with -c, a stdin/file script, or a pipe sink.
  if (SHELL_INTERPRETERS.has(verb) && (seg.readsInput || seg.pipedInto || hasMinusC(tokens))) {
    return `bash-destructive-guard: shell interpreter '${verb}' running a script from -c, stdin/file, or a pipeline sink is not permitted (bypass vector).

This is a hard refusal — do not retry by re-wrapping the same payload. The bypass intent itself is what is blocked, not the wrapped command. If the wrapped command is legitimate, invoke it directly without the \`${verb}\` wrapper (no \`-c\`, no \`<<\`/\`<<<\`, no \`| ${verb}\`) so each verb can be evaluated on its own merits.`;
  }

  // Rule 2 — exec-wrapper whose token list contains a destructive operation
  // (rm/mv/dd/truncate, find -delete, or a quote-embedded clobber redirect).
  if (WRAPPER_VERBS.has(verb) && wrapsDestructive(tokens)) {
    return `bash-destructive-guard: '${verb}' wraps a destructive operation (rm/mv/dd/truncate, find -delete, or a redirect) — refusing for safety (the wrapped target cannot be statically validated).

Suggested alternatives:
  - Invoke the destructive command directly (e.g. \`rm <path>\`) without the \`${verb}\` wrapper so the path can be evaluated against the safe list.
  - If you must use \`${verb}\`, scope the operation under \`/tmp\` or cwd, or set \`SKIP_DESTRUCTIVE_GUARD=1\` for a one-off.`;
  }

  // Rule 4 — find -delete (find is also a wrapper; rule 2 covers `-exec rm`).
  if (verb === "find") {
    const reason = checkFindDelete(tokens, safePaths);
    if (reason) return reason;
  }

  // Rule 3 — rm/mv path check.
  if (DESTRUCTIVE_VERBS.has(verb)) {
    const reason = checkDestructivePaths(verb, tokens, safePaths);
    if (reason) return reason;
  }

  // Rule 5 — dd of=
  if (verb === "dd") {
    const reason = checkDd(tokens, safePaths);
    if (reason) return reason;
  }

  // Rule 6 — truncate -s
  if (verb === "truncate") {
    const reason = checkTruncate(tokens, safePaths);
    if (reason) return reason;
  }

  return null;
}

export default function (pi: ExtensionAPI) {
  const skipGeneral = process.env.SKIP_DESTRUCTIVE_GUARD === "1";
  // The report-only profile (#551, ADR-0091) is read at load time: the env
  // var is set by the PARENT (subagent spawn path) before this process
  // starts, so an in-session `export PI_GUARD_PROFILE=` cannot un-certify
  // the agent.
  const profileActive = isReportOnlyProfileActive();
  // AST second-pass posture (strict mode + resolved parser path) is likewise
  // captured ONCE at load, for the same reason: an in-session env mutation must
  // not downgrade strict->additive or repoint the binary mid-session (#506).
  const astCfg = initAstConfig();

  if (skipGeneral) {
    // Session-wide bypass of the GENERAL rules. Announce via notify per
    // ADR-0022 § Q5 "override cannot be silent" contract (backported from
    // gh-identity-guard — issue #258). The report-only profile deliberately
    // survives the bypass: SKIP_DESTRUCTIVE_GUARD waives the blast-radius
    // guard, not the wrapper's report-only contract (ADR-0091).
    pi.on("session_start", (_event, ctx) => {
      if (!ctx.hasUI) return;
      ctx.ui.notify(
        profileActive
          ? "bash-destructive-guard: general rules bypassed via SKIP_DESTRUCTIVE_GUARD=1; report-only profile remains active"
          : "bash-destructive-guard: bypassed via SKIP_DESTRUCTIVE_GUARD=1",
        "warning",
      );
    });
    if (!profileActive) return;
  }

  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName !== "bash") return undefined;

    const raw = String((event.input as { command?: string }).command ?? "").trim();
    if (!raw) return undefined;

    const block = (reason: string) => {
      if (ctx.hasUI) ctx.ui.notify(reason, "error");
      return { block: true, reason };
    };

    // Safe-list entries are canonicalized once per call so both sides of the
    // isUnderSafePath comparison are in resolved form (#554).
    const safePaths = ["/tmp", ctx.cwd, ...loadUserSafePaths()].map(canonicalize);
    const command = preprocessCommand(raw);
    // Analyze the command AND a deglued variant (word-internal empty command
    // substitutions removed) so `r$(true)m` is caught. A rule tripping in
    // either variant blocks; deduped when degluing is a no-op.
    const deglued = deglueWordSubstitutions(command);
    const variants = deglued === command ? [command] : [command, deglued];

    for (const variant of variants) {
      for (const seg of lex(variant)) {
        if (profileActive) {
          const profileReason = analyzeReportOnlySegment(seg);
          if (profileReason) return block(profileReason);
        }
        if (!skipGeneral) {
          const reason = analyzeSegment(seg, safePaths);
          // Under the profile, scrub override advertisements from any
          // general-rule denial that fires (ADR-0091 — no profile-reachable
          // message may name a self-service override).
          if (reason) return block(profileActive ? sanitizeGeneralDenyForProfile(reason) : reason);
        }
      }
    }

    // AST second opinion (#506, ADR-0100): only for substitution / ANSI-C
    // shapes the hand-lexer cannot resolve, and only when the hand-lexer found
    // nothing above. The parser returns segments; we re-apply the SAME two
    // policies the hand-lexer loop above uses (report-only profile, then the
    // general blast-radius policy), so the AST pass extends BOTH contracts —
    // not just the general one. Additive by default; strict mode adds a meta
    // denial on parser-unavailable / parse-failure.
    if (profileActive || !skipGeneral) {
      const ast = await astSecondPass(command, astCfg);
      if (ast.kind === "deny") {
        return block(profileActive ? sanitizeGeneralDenyForProfile(ast.reason) : ast.reason);
      }
      if (ast.kind === "segments") {
        for (const seg of ast.segments) {
          if (profileActive) {
            const profileReason = analyzeReportOnlySegment(seg);
            if (profileReason) return block(profileReason);
          }
          if (!skipGeneral) {
            const reason = analyzeSegment(seg, safePaths);
            if (reason) return block(profileActive ? sanitizeGeneralDenyForProfile(reason) : reason);
          }
        }
      }
    }

    return undefined;
  });
}
