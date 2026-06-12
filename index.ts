/**
 * bash-destructive-guard — pi extension
 *
 * Denies bash tool calls that invoke destructive verbs (`rm`, `mv`) against
 * paths outside a configurable safe list. Mirrors the framework's
 * hooks/bash-destructive-guard.sh but runs as a pi extension hooked on the
 * `tool_call` event for `bash`.
 *
 * THREAT MODEL (read this before "fixing" a bypass):
 *   This guard provides BLAST-RADIUS ISOLATION against the agent issuing a
 *   *naive or mistaken* destructive command — `rm /etc/foo`, `rm;rm /x`,
 *   `sudo rm`, `eval 'rm ...'`, a pasted one-liner, etc. It is NOT a sandbox
 *   and NOT a defense against an adversary who is deliberately crafting
 *   shell to evade it: anyone with bash and intent can use ANSI-C quoting
 *   (`$'\x72m'`), parameter-default expansion (`${x:-rm}`), variable
 *   indirection (`R=rm; $R /x`), or simply set SKIP_DESTRUCTIVE_GUARD=1.
 *   Static analysis of shell is undecidable; we catch the realistic
 *   accidental cases and document the rest (see "Residual gaps" below).
 *
 * Safe paths:
 *   - Built-in: /tmp, the current pi cwd (and anything beneath it)
 *   - User-extendable via ~/.config/pi/bash-guard-safe-paths.conf
 *     (one path per line, blank lines and # comments ignored)
 *
 * Override:
 *   - SKIP_DESTRUCTIVE_GUARD=1 in pi's env (extension loads but no hook)
 *
 * Detection model (#297):
 *   Preprocess: collapse `\<newline>` line continuations, strip heredoc
 *   bodies (their content is data, not commands), and normalize
 *   `$IFS`/`${IFS}` to a space. Then run a small QUOTE-AWARE lexer that
 *   splits into command-position segments on unquoted control operators and
 *   group/subshell/substitution boundaries (`;`, `|`, `&`, `(`, `)`,
 *   newline, backtick), tracks whether a segment reads from stdin/a file
 *   (`<`, `<<`, `<<<`), and strips surrounding quotes / escaping backslashes
 *   from each token. Leading `NAME=value` env assignments (including quoted
 *   multi-word values) are dropped so the real verb surfaces.
 *
 *   Per segment:
 *     1. Shell-interpreter verb (bash/sh/...) with `-c` OR reading a script
 *        from stdin/file (`<`/`<<`/`<<<`)   → DENY (bypass vector)
 *     2. Exec-wrapper verb (eval/xargs/sudo/...) whose token list contains
 *        `rm`/`mv` as a standalone token     → DENY (wrapped target is not
 *                                               statically validatable)
 *     3. Verb is rm or mv                     → check path tokens
 *        - metachar / `..` / outside-safe-and-absolute → DENY; else allow
 *     4. Anything else                        → allow
 *
 *   Because `$(...)`/backtick/subshell bodies become their own segments, a
 *   destructive verb inside them is path-validated directly (safe paths
 *   allowed, unsafe blocked) rather than waved through or blunt-blocked.
 *
 * Residual gaps (fail-open by design; adversarial, not accidental):
 *   - ANSI-C-quoted verbs/flags: `$'\x72m' /x`, `bash $'-c\nrm /x'`
 *   - parameter-default expansion: `${x:-rm} /x`
 *   - variable indirection: `R=rm; $R /x`
 *   - eval of a command substitution: `eval "$(printf rm) /x"`
 *   These require runtime expansion the guard does not perform. Out of scope
 *   entirely (different verbs): `>` clobber, `find -delete`, `truncate`,
 *   `dd of=`, `python -c 'os.remove(...)'`.
 *
 * Source rule: this extension is the runtime counterpart to
 * agent/rules/secrets-guard.md's "blast-radius isolation" principle.
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const SHELL_INTERPRETERS = new Set(["bash", "sh", "dash", "zsh", "ksh", "busybox"]);
// Exec-wrappers that run another command and would otherwise hide a leading
// destructive verb. We do not parse their argument grammar; if the segment's
// token list contains rm|mv we fail closed.
const WRAPPER_VERBS = new Set([
  "eval",
  "xargs",
  "env",
  "nohup",
  "command",
  "sudo",
  "doas",
  "su",
  "runuser",
  "timeout",
  "time",
  "nice",
  "ionice",
  "stdbuf",
  "setsid",
  "watch",
  "flock",
  "parallel",
  "unshare",
  "chroot",
  "exec",
  "find",
]);
const DESTRUCTIVE_VERBS = new Set(["rm", "mv"]);
const META_CHAR_RE = /[$`|;&(){}]/;
// Leading `NAME=value` environment-assignment prefix (e.g. `FOO=bar cmd ...`).
const ENV_ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;
// `$IFS` / `${IFS}` separator-obfuscation; normalized to a space.
const IFS_RE = /\$\{IFS\}|\$IFS/g;

interface Segment {
  tokens: string[];
  /** segment reads a script from stdin/a file (`<`, `<<`, `<<<`). */
  readsInput: boolean;
}

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

// Remove heredoc bodies (their content is data, not executed commands). The
// introducing line (e.g. `cat <<EOF`, `bash <<EOF`) is kept and still
// analyzed — a shell interpreter reading a heredoc script is caught by the
// stdin-redirect check, while a data heredoc (`cat`) is harmless.
function stripHeredocs(command: string): string {
  const lines = command.split("\n");
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    out.push(line);
    const m = line.match(/<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1/);
    if (!m) continue;
    const delim = m[2];
    const allowTab = line.includes("<<-");
    while (i + 1 < lines.length) {
      i++;
      const body = allowTab ? lines[i].replace(/^\t+/, "") : lines[i];
      if (body === delim) break;
    }
  }
  return out.join("\n");
}

// Quote-aware lexer. Splits into command-position segments on unquoted
// control operators / group boundaries, strips quotes and escaping
// backslashes from tokens, and records stdin/file redirection. NOT a full
// POSIX parser — see THREAT MODEL.
function lex(command: string): Segment[] {
  const segments: Segment[] = [];
  let tokens: string[] = [];
  let cur = "";
  let curUsed = false; // distinguishes a real empty-quote token "" from no token
  let readsInput = false;
  let inSingle = false;
  let inDouble = false;

  const endToken = () => {
    if (cur.length > 0 || curUsed) tokens.push(cur);
    cur = "";
    curUsed = false;
  };
  const endSegment = () => {
    endToken();
    if (tokens.length > 0 || readsInput) segments.push({ tokens, readsInput });
    tokens = [];
    readsInput = false;
  };

  for (let i = 0; i < command.length; i++) {
    const c = command[i];

    if (inSingle) {
      if (c === "'") inSingle = false;
      else {
        cur += c;
        curUsed = true;
      }
      continue;
    }
    if (inDouble) {
      if (c === '"') {
        inDouble = false;
      } else if (c === "\\" && i + 1 < command.length && '"\\$`'.includes(command[i + 1])) {
        cur += command[++i];
        curUsed = true;
      } else {
        cur += c;
        curUsed = true;
      }
      continue;
    }

    if (c === "'") {
      inSingle = true;
      curUsed = true;
      continue;
    }
    if (c === '"') {
      inDouble = true;
      curUsed = true;
      continue;
    }
    if (c === "\\") {
      if (i + 1 < command.length) {
        cur += command[++i];
        curUsed = true;
      }
      continue;
    }
    if (c === ";" || c === "|" || c === "&" || c === "(" || c === ")" || c === "\n" || c === "`") {
      endSegment();
      continue;
    }
    if (c === "<") {
      endToken();
      readsInput = true;
      continue;
    }
    if (c === ">") {
      endToken();
      continue;
    }
    if (c === " " || c === "\t" || c === "\r") {
      endToken();
      continue;
    }
    cur += c;
    curUsed = true;
  }
  endSegment();
  return segments;
}

// Drop leading `NAME=value` env-assignment tokens so the real verb surfaces.
function stripEnvAssignments(tokens: string[]): string[] {
  let i = 0;
  while (i < tokens.length && ENV_ASSIGN_RE.test(tokens[i])) i++;
  return tokens.slice(i);
}

function hasMinusC(tokens: string[]): boolean {
  // `-c` or a single-dash short-option cluster containing `c` (`-ec`, `-xc`).
  return tokens.some((t) => t === "-c" || /^-[A-Za-z]*c[A-Za-z]*$/.test(t));
}

// True if any wrapped token contains rm|mv as a standalone WORD. Word-level
// (not token-exact) so a wrapped command string carried in one quoted token
// (`eval 'rm /x'`, `su -c 'rm /x'`) is detected, while a path component
// named rm/mv (`/home/rm/file`) is not.
function wrapsDestructive(tokens: string[]): boolean {
  for (const t of tokens.slice(1)) {
    for (const w of t.split(/\s+/)) {
      if (w === "rm" || w === "mv") return true;
    }
  }
  return false;
}

function isUnderSafePath(target: string, safePaths: string[]): boolean {
  for (const sp of safePaths) {
    if (target === sp) return true;
    if (target.startsWith(sp.endsWith("/") ? sp : sp + "/")) return true;
  }
  return false;
}

// Returns a block reason if a destructive verb targets an unsafe path, else null.
function checkDestructivePaths(
  verb: string,
  tokens: string[],
  safePaths: string[],
): string | null {
  const pathTokens: string[] = [];
  let pastDashDash = false;
  for (const t of tokens.slice(1)) {
    if (t === "--") {
      pastDashDash = true;
      continue;
    }
    if (pastDashDash || !t.startsWith("-")) pathTokens.push(t);
  }

  if (pathTokens.length === 0) return null; // flags-only — harmless

  for (const p of pathTokens) {
    if (META_CHAR_RE.test(p)) {
      return `bash-destructive-guard: '${verb}' path '${p}' contains shell metacharacters — refusing for safety.

Suggested alternatives:
  - Expand the glob or variable yourself and issue \`${verb}\` with an explicit literal path.
  - If you want to remove every file matching a pattern, use \`ls <pattern>\` first to confirm the list, then \`${verb}\` each path individually.`;
    }
    if (p.includes("..")) {
      return `bash-destructive-guard: '${verb}' path '${p}' contains '..' traversal — refusing for safety.

Suggested alternatives:
  - Resolve the path to its absolute form and issue \`${verb}\` with the absolute path.
  - If the intent was relative to cwd, drop the \`..\` segments and use the direct relative path.`;
    }

    // Relative paths (not starting with /) are implicitly within cwd
    // and therefore inside the safe list.
    if (!p.startsWith("/")) continue;

    if (!isUnderSafePath(p, safePaths)) {
      return `bash-destructive-guard: '${verb} ${p}' — path outside safe list (${safePaths.join(", ")}).

Suggested alternatives:
  - If the operation belongs inside the project, use a path relative to cwd instead of an absolute path.
  - If the operation is legitimately outside the project, add the parent directory to \`~/.config/pi/bash-guard-safe-paths.conf\` (one path per line) and retry.
  - If you only need a scratch location, work under \`/tmp\` — already in the safe list.
  - Last resort for a one-off destructive operation: set \`SKIP_DESTRUCTIVE_GUARD=1\` in the pi session env.`;
    }
  }
  return null;
}

export default function (pi: ExtensionAPI) {
  if (process.env.SKIP_DESTRUCTIVE_GUARD === "1") {
    // Session-wide bypass. Announce via notify per ADR-0022 § Q5
    // "override cannot be silent" contract (backported from
    // gh-identity-guard — issue #258). Extension loads but installs no
    // tool_call handler.
    pi.on("session_start", (_event, ctx) => {
      if (!ctx.hasUI) return;
      ctx.ui.notify(
        "bash-destructive-guard: bypassed via SKIP_DESTRUCTIVE_GUARD=1",
        "warning",
      );
    });
    return;
  }

  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName !== "bash") return undefined;

    const raw = String((event.input as { command?: string }).command ?? "").trim();
    if (!raw) return undefined;

    const block = (reason: string) => {
      if (ctx.hasUI) ctx.ui.notify(reason, "error");
      return { block: true, reason };
    };

    const safePaths = ["/tmp", ctx.cwd, ...loadUserSafePaths()];
    // Preprocess: collapse line continuations, strip heredoc bodies, normalize $IFS.
    const command = stripHeredocs(raw.replace(/\\\n/g, "")).replace(IFS_RE, " ");

    for (const seg of lex(command)) {
      const tokens = stripEnvAssignments(seg.tokens);
      if (tokens.length === 0) continue;
      // Basename-normalize the verb so an absolute/relative path to the
      // binary (`/bin/rm`, `/usr/bin/sudo`) classifies like its basename.
      const rawVerb = tokens[0];
      const verb = rawVerb.split("/").pop() || rawVerb;

      // 1. Shell interpreter with -c or a stdin/file script is a bypass vector.
      if (SHELL_INTERPRETERS.has(verb) && (seg.readsInput || hasMinusC(tokens))) {
        return block(
          `bash-destructive-guard: shell interpreter '${verb}' running a script from -c or stdin/file is not permitted (bypass vector).

This is a hard refusal — do not retry by re-wrapping the same payload. The bypass intent itself is what is blocked, not the wrapped command. If the wrapped command is legitimate, invoke it directly without the \`${verb}\` wrapper (no \`-c\`, no \`<<\`/\`<<<\`) so each verb can be evaluated on its own merits.`,
        );
      }

      // 2. Exec-wrapper whose token list contains a destructive verb.
      if (WRAPPER_VERBS.has(verb) && wrapsDestructive(tokens)) {
        return block(
          `bash-destructive-guard: '${verb}' wraps a destructive verb (rm|mv) — refusing for safety (the wrapped target cannot be statically validated).

Suggested alternatives:
  - Invoke the destructive command directly (e.g. \`rm <path>\`) without the \`${verb}\` wrapper so the path can be evaluated against the safe list.
  - If you must use \`${verb}\`, scope the operation under \`/tmp\` or cwd, or set \`SKIP_DESTRUCTIVE_GUARD=1\` for a one-off.`,
        );
      }

      // 3. Plain destructive-verb invocation — check path tokens.
      if (DESTRUCTIVE_VERBS.has(verb)) {
        const reason = checkDestructivePaths(verb, tokens, safePaths);
        if (reason) return block(reason);
      }
    }

    return undefined;
  });
}
