/**
 * shared/shell-lex.ts — quote-aware shell command lexer (Pi Extension Suite foundation).
 *
 * The parsing half of the bash-guard family, extracted from
 * bash-destructive-guard so sibling guards (e.g. secrets-guard, issue #505) can
 * consume ONE hardened primitive instead of re-implementing command
 * segmentation. Policy — which verbs/paths are destructive — stays in the
 * consuming extension; this module only turns a raw bash string into
 * command-position segments.
 *
 * THREAT MODEL (read before "fixing" a bypass):
 *   This is a QUOTE-AWARE LEXER, not a POSIX shell parser. It models bash's
 *   word-splitting and quoting well enough to catch a naive or lightly
 *   obfuscated command; it does NOT resolve runtime expansion. Value-dependent
 *   evasions — a `$VAR` whose value contains whitespace (Class B), the output
 *   of a command substitution or decode pipeline (Classes C/D) — are provably
 *   undecidable without executing untrusted code and remain fail-open by
 *   design. The sound boundary is below the shell (execve/sandbox, issue #507).
 *   See ADR-0072.
 *
 * What it DOES model (GuardFall classes A–D, string-decidable subset):
 *   - Class A quote-splitting (`r''m` → one word `rm`): tokens are joined
 *     across quote boundaries exactly as bash joins adjacent quoted runs.
 *   - Class B literal `$IFS`/`${IFS}`: normalized to a space by
 *     `preprocessCommand` (word-boundary anchored so `$IFSX` is left alone).
 *   - Class C command substitution: `$(...)`/backtick bodies become their own
 *     segments (so a destructive verb inside is validated directly); the GLUED
 *     empty-substitution shape (`r$(true)m`) is handled conservatively by
 *     `deglueWordSubstitutions` (see its doc).
 *   - Class D pipe sinks: a segment reached via a single `|` is marked
 *     `pipedInto`, so a consumer can treat `… | sh` like `sh <script`.
 *
 * Redirections are captured (`readsInput` for `<`/`<<`/`<<<`; `redirects[]` for
 * `>`/`>|`/`>>` with their targets) so a consumer can gate stdin-script
 * interpreters and output-clobber writes.
 */

/** A captured output redirection and its target path. */
export interface Redirect {
  /** `>` (clobber), `>|` (forced clobber), `>>` (append). */
  op: string;
  /** Redirect target token (quote-stripped). */
  target: string;
}

export interface Segment {
  /** Command-position tokens, quote- and escape-stripped. */
  tokens: string[];
  /** Segment reads a script from stdin/a file (`<`, `<<`, `<<<`). */
  readsInput: boolean;
  /** Segment is the downstream stage of a single `|` pipe (not `||`). */
  pipedInto: boolean;
  /** Output redirections (`>`, `>|`, `>>`) with captured targets. */
  redirects: Redirect[];
}

/** `$IFS` / `${IFS}` separator-obfuscation. Anchored so `$IFSX` is not mangled. */
const IFS_RE = /\$\{IFS\}|\$IFS(?![A-Za-z0-9_])/g;

/** Leading `NAME=value` environment-assignment prefix (e.g. `FOO=bar cmd ...`). */
const ENV_ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

/**
 * A command substitution glued to a word character on BOTH sides — the
 * `r$(true)m` obfuscation. Both-sides-glued is the key discriminator: a
 * substitution used as a real value is space-separated (`rm $(echo /tmp)/x`)
 * and is NOT matched, so degluing never rewrites a legitimate path argument.
 * `[^()`]*` keeps the body flat; nested substitutions are peeled by the
 * fixpoint loop in `deglueWordSubstitutions`.
 */
const GLUED_SUBST_RE = /(?<=[A-Za-z0-9_])(?:\$\([^()]*\)|`[^`]*`)(?=[A-Za-z0-9_])/g;

/**
 * Remove heredoc bodies (their content is data, not executed commands). The
 * introducing line (e.g. `cat <<EOF`, `bash <<EOF`) is kept and still
 * analyzed — a shell interpreter reading a heredoc script is caught by the
 * stdin-redirect check, while a data heredoc (`cat`) is harmless.
 */
export function stripHeredocs(command: string): string {
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

/**
 * Preprocess a raw command: collapse `\<newline>` line continuations, strip
 * heredoc bodies, and normalize `$IFS`/`${IFS}` to a space. This is the
 * canonical first pass before `lex`.
 */
export function preprocessCommand(raw: string): string {
  return stripHeredocs(raw.replace(/\\\n/g, "")).replace(IFS_RE, " ");
}

/**
 * Produce a deobfuscated variant by removing command substitutions glued into
 * a word on both sides (treating them as the empty string they usually expand
 * to — `$(true)`, `$(:)`, backtick-noops). `r$(true)m` → `rm`, so a consumer
 * re-running its policy over this variant catches the glued-verb obfuscation,
 * while space-separated value substitutions are left untouched (no path-arg
 * false positives). Returns the input unchanged when nothing is glued.
 *
 * CONSERVATIVE by design (ADR-0072 Q3.A): it only unmasks substitutions that
 * expand to nothing. A substitution that PRODUCES the verb text (`$(echo r)m`)
 * or hides the binary name entirely (`$(echo rm) -rf /`) is value-dependent and
 * remains a documented fail-open gap pending the AST parser (issue #506).
 */
export function deglueWordSubstitutions(command: string): string {
  let prev: string;
  let out = command;
  // Fixpoint: peel nested/adjacent glued substitutions (`r$(a)$(b)m`).
  do {
    prev = out;
    out = out.replace(GLUED_SUBST_RE, "");
  } while (out !== prev);
  return out;
}

/**
 * Quote-aware lexer. Splits into command-position segments on unquoted control
 * operators / group boundaries, strips quotes and escaping backslashes from
 * tokens, and records stdin/file redirection, pipe-sink position, and output
 * redirections. NOT a full POSIX parser — see THREAT MODEL.
 */
export function lex(command: string): Segment[] {
  const segments: Segment[] = [];
  let tokens: string[] = [];
  let redirects: Redirect[] = [];
  let cur = "";
  let curUsed = false; // distinguishes a real empty-quote token "" from no token
  let readsInput = false;
  let pipedInto = false; // set for the segment AFTER a single `|`
  let pendingRedirectOp: string | null = null;
  let inSingle = false;
  let inDouble = false;

  const endToken = () => {
    if (cur.length > 0 || curUsed) {
      if (pendingRedirectOp !== null) {
        redirects.push({ op: pendingRedirectOp, target: cur });
        pendingRedirectOp = null;
      } else {
        tokens.push(cur);
      }
    }
    cur = "";
    curUsed = false;
  };
  const endSegment = (nextPiped: boolean) => {
    endToken();
    if (tokens.length > 0 || readsInput || redirects.length > 0) {
      segments.push({ tokens, readsInput, pipedInto, redirects });
    }
    tokens = [];
    redirects = [];
    readsInput = false;
    pendingRedirectOp = null;
    pipedInto = nextPiped;
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
    if (c === "|") {
      // `||` is logical-OR (a fallback command, not a pipe sink); a single `|`
      // pipes stdout into the next segment's stdin.
      if (command[i + 1] === "|") {
        endSegment(false);
        i++;
      } else {
        endSegment(true);
      }
      continue;
    }
    if (c === ";" || c === "&" || c === "(" || c === ")" || c === "\n" || c === "`") {
      endSegment(false);
      continue;
    }
    if (c === "<") {
      endToken();
      readsInput = true;
      while (command[i + 1] === "<") i++; // collapse `<<` / `<<<`
      continue;
    }
    if (c === ">") {
      endToken();
      let op = ">";
      if (command[i + 1] === ">") {
        op = ">>";
        i++;
      } else if (command[i + 1] === "|") {
        op = ">|";
        i++;
      }
      pendingRedirectOp = op;
      continue;
    }
    if (c === " " || c === "\t" || c === "\r") {
      endToken();
      continue;
    }
    cur += c;
    curUsed = true;
  }
  endSegment(false);
  return segments;
}

/** Drop leading `NAME=value` env-assignment tokens so the real verb surfaces. */
export function stripEnvAssignments(tokens: string[]): string[] {
  let i = 0;
  while (i < tokens.length && ENV_ASSIGN_RE.test(tokens[i])) i++;
  return tokens.slice(i);
}

/** `-c`, or a single-dash short-option cluster containing `c` (`-ec`, `-xc`). */
export function hasMinusC(tokens: string[]): boolean {
  return tokens.some((t) => t === "-c" || /^-[A-Za-z]*c[A-Za-z]*$/.test(t));
}
