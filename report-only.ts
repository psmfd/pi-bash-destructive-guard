/**
 * bash-destructive-guard/report-only.ts — the report-only guard profile
 * (pi_config #551, ADR-0091).
 *
 * WHAT
 * ----
 * When the spawning orchestrator sets PI_GUARD_PROFILE=report-only in a
 * subagent's environment (wired from the wrapper's `guard-profile`
 * frontmatter by the subagent extension), this module adds a linter-scoped
 * mutation gate ON TOP of the general destructive-guard rules: fix-flag
 * invocations (`eslint --fix`, `ruff format`, `dotnet format` without
 * `--verify-no-changes`, …), in-place editors (`sed -i`, `perl -i`, `tee`),
 * ANY output redirect or file-mutation verb targeting a non-/tmp path —
 * relative, in-cwd paths included (the #535 hole: `cat > transform.py`
 * sailed past the general guard because in-cwd writes are inside its
 * blast-radius threat model), git/package-manager mutations, and the
 * shell-interpreter bypass shapes.
 *
 * The general guard answers "could this destroy something outside the
 * workspace?"; this profile answers "does this WRITE at all?" — because a
 * report-only agent's contract is to report, never to apply.
 *
 * OVERRIDE POSTURE (deliberate, see ADR-0082's causal-attribution lesson)
 * ----------------------------------------------------------------------
 * The profile is set by the PARENT at spawn time; the child agent cannot
 * un-certify itself. Deny messages MUST NOT advertise a self-service
 * override: in the #535 evaluation the general guard's own denial text
 * taught the model to prefix SKIP_DESTRUCTIVE_GUARD=1 and finish the
 * mutation. SKIP_DESTRUCTIVE_GUARD=1 deliberately does NOT disable this
 * profile (index.ts keeps the profile handler installed either way): SKIP
 * bypasses the blast-radius guard, not the wrapper's contract. The only
 * ways out are legitimate: the orchestrator spawns a wrapper without the
 * frontmatter key, or the operator edits the wrapper.
 *
 * THREAT MODEL — same class as the parent guard (see index.ts header):
 * discipline enforcement against a naive or instruction-following model,
 * NOT a sandbox against adversarial shell. ANSI-C quoting and nested command
 * substitution are now caught for THIS profile too when the pi-bash-parser AST
 * second pass is available (#506, ADR-0100 — index.ts applies this profile's
 * analyzeReportOnlySegment to the AST-discovered segments, not only the general
 * policy). Variable indirection, runtime-decoded payloads, and second-
 * interpreter files (`make lint` whose recipe rewrites sources) remain out of
 * scope (#507). Scratch writes under /tmp stay allowed so linters can work.
 */

import { hasMinusC, stripEnvAssignments, type Segment } from "./shared/shell-lex.ts";
import { canonicalize } from "./paths.ts";
import { SHELL_INTERPRETERS, WRAPPER_VERBS } from "./policy-verbs.ts";

export function isReportOnlyProfileActive(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.PI_GUARD_PROFILE === "report-only";
}

const CONTRACT = `

This subagent runs under a report-only contract set by the spawning orchestrator: run the tools in check/report mode and return findings — the orchestrator decides whether fixes are applied. The profile cannot be overridden from inside this session; re-issue the command in its non-mutating form (e.g. drop the fix/write flag, or target /tmp for scratch output).`;

function deny(what: string): string {
  return `bash-destructive-guard [report-only profile]: ${what}${CONTRACT}`;
}

/**
 * Belt-and-braces for general-rule denials that fire while the profile is
 * active: strip any line advertising a self-service override
 * (SKIP_DESTRUCTIVE_GUARD, the safe-paths conf) and append the report-only
 * contract, so no profile-reachable message can reproduce the #535 sequence
 * where the guard's own text taught the model the bypass (ADR-0082 lesson).
 */
export function sanitizeGeneralDenyForProfile(reason: string): string {
  const scrubbed = reason
    .split("\n")
    .filter((l) => !/SKIP_DESTRUCTIVE_GUARD|bash-guard-safe-paths\.conf|PI_BASH_GUARD_AST_STRICT/.test(l))
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trimEnd();
  return scrubbed + CONTRACT;
}

// Mutating flags denied on ANY verb, matched word-level across the whole
// segment (including inside quoted wrapper payloads, mirroring
// wrapsDestructive's word-split scan in index.ts).
const MUTATING_FLAGS = new Set([
  "--fix",
  "--fix-only",
  "--unsafe-fixes",
  "--write",
  "--apply",
  "--in-place",
  "--edit",
  "--autofix",
]);

// File-mutation verbs whose EVERY path operand is a write target: allowed
// only when each canonicalizes under /tmp. Relative operands resolve to cwd
// and are therefore denied.
const TMP_ONLY_ALL_OPERANDS = new Set([
  "rm",
  "rmdir",
  "mkdir",
  "touch",
  "truncate",
  "chmod",
  "chown",
  "tee",
  "sponge",
]);

// Copy/move/link shapes: sources are reads; only the LAST path operand is
// the write target (`cp transform.py /tmp/check.py` is a legitimate scratch
// copy). `mv` also mutates its source path, so it checks every operand.
const TMP_ONLY_DEST_OPERAND = new Set(["cp", "ln", "install"]);

// git subcommands a report-only agent legitimately needs. Everything else
// (add/commit/apply/checkout/restore/reset/clean/stash/push/…) is denied.
const GIT_READONLY = new Set([
  "status",
  "diff",
  "log",
  "show",
  "grep",
  "ls-files",
  "ls-tree",
  "blame",
  "rev-parse",
  "rev-list",
  "describe",
  // `branch`/`remote`/`config` are NOT allowlisted: their mutating forms
  // (`git branch -d`, `git remote add`, `git config --file <path> k v` —
  // the last a genuine arbitrary-file write) are indistinguishable by
  // subcommand name alone, and a linter has no need for any of them.
  "var",
  "cat-file",
  "check-ignore",
  "help",
  "version",
  "--version",
]);

// Package managers: every verb denied (install/run/exec mutate or execute
// arbitrary scripts). `npx <tool>` is the one sanctioned launcher shape —
// its wrapped tool's own flags are still scanned by the word-level checks.
const PKG_MANAGERS = new Set(["npm", "yarn", "pnpm", "pip", "pip3", "pipx", "gem", "bun"]);

// cargo subcommands a lint pass legitimately uses; `cargo fmt` additionally
// requires --check (R4). install/run/build/test are denied (execute or write).
const CARGO_READONLY = new Set(["fmt", "check", "clippy", "metadata", "tree", "version", "--version"]);

// Mutating verb WORDS scanned inside exec-wrapper token lists (word-level,
// mirroring the general guard's wrapsDestructive): a wrapper whose payload
// names any of these is denied, closing the `eval 'sed -i …'` /
// `sudo tee notes.md` / `xargs chmod` routing hole the verb-position rules
// cannot see. Deliberately includes verbs whose direct (unwrapped) form is
// conditionally allowed — a linter has no cause to route even a /tmp write
// through a wrapper, and fail-closed keeps the rule simple.
const MUTATING_VERB_WORDS = new Set([
  "rm",
  "mv",
  "cp",
  "ln",
  "install",
  "mkdir",
  "rmdir",
  "touch",
  "truncate",
  "chmod",
  "chown",
  "tee",
  "sponge",
  "sed",
  "gsed",
  "perl",
  "dd",
  "git",
  "npm",
  "yarn",
  "pnpm",
  "pip",
  "pip3",
  "pipx",
  "gem",
  "bun",
]);

// Transparent prefix wrappers: the wrapped command follows directly in argv
// (after the wrapper's own flags/duration/assignments), so the profile can
// RECURSE and apply its full rule set to the real verb. Subset of
// policy-verbs.ts WRAPPER_VERBS; the rest are opaque (quoted/deferred
// payloads) and get the fail-closed word-scan instead.
const TRANSPARENT_PREFIX_WRAPPERS = new Set([
  "sudo",
  "doas",
  "env",
  "command",
  "nohup",
  "timeout",
  "time",
  "nice",
  "ionice",
  "stdbuf",
  "setsid",
]);

// Words denied inside OPAQUE wrapper payloads (`eval`, `xargs`, `su`, …):
// the unconditional mutating verbs PLUS the conditionally-allowed tools
// whose check-vs-write mode cannot be resolved inside an unparsed payload
// (closure-verification finding: `eval 'black src/'` / `xargs gofmt -w`
// were zero-signal bypasses). Direct invocation remains the sanctioned —
// and rule-evaluable — form for all of these.
const WRAPPED_DENY_WORDS = new Set([
  ...MUTATING_VERB_WORDS,
  "ruff",
  "black",
  "isort",
  "rustfmt",
  "swiftformat",
  "autopep8",
  "yapf",
  "clang-format",
  "gofmt",
  "goimports",
  "shfmt",
  "prettier",
  "eslint",
  "dotnet",
  "terraform",
  "go",
  "cargo",
  "markdownlint",
  "markdownlint-cli2",
]);

// Formatters that WRITE by default: denied unless a recognized check/diff
// flag is present.
const DEFAULT_WRITE_FORMATTERS: Record<string, string[]> = {
  rustfmt: ["--check"],
  black: ["--check", "--diff"],
  isort: ["--check", "--check-only", "--diff"],
  swiftformat: ["--lint", "--dryrun"],
};

// In-place editors taking a short `-i` (distinct from sed/perl's suffix
// forms): autopep8, yapf, clang-format.
const SHORT_I_INPLACE_TOOLS = new Set(["autopep8", "yapf", "clang-format"]);

const TMP_CANON = canonicalize("/tmp");

function underTmp(p: string): boolean {
  if (!p.startsWith("/")) return false; // relative → cwd → not /tmp
  const canon = canonicalize(p);
  return canon === TMP_CANON || canon.startsWith(`${TMP_CANON}/`);
}

// Flags that consume the NEXT token as a value (not a path), per verb —
// without this, `mkdir -m 755 /tmp/x` / `truncate -s 0 /tmp/y` would treat
// the mode/size value as a path operand and falsely deny (false denials are
// the ADR-0082 mechanism that drove a model toward hunting for an override).
const VALUE_FLAGS: Record<string, Set<string>> = {
  mkdir: new Set(["-m", "--mode"]),
  truncate: new Set(["-s", "--size"]),
  ln: new Set(["-S", "--suffix", "-t", "--target-directory"]),
  install: new Set(["-m", "--mode", "-o", "--owner", "-g", "--group", "-t", "--target-directory"]),
};

// Verbs whose FIRST non-flag operand is not a path (chmod's mode, chown's
// owner[:group]).
const FIRST_OPERAND_NOT_PATH = new Set(["chmod", "chown"]);

// Path operands = non-flag tokens after the verb (honoring `--`, skipping
// per-verb value-flag arguments and non-path leading operands).
function pathOperands(tokens: string[]): string[] {
  const verb = basenameOf(tokens[0]);
  const valueFlags = VALUE_FLAGS[verb];
  const out: string[] = [];
  let pastDashDash = false;
  let skipNext = false;
  for (const t of tokens.slice(1)) {
    if (skipNext) {
      skipNext = false;
      continue;
    }
    if (!pastDashDash && t === "--") {
      pastDashDash = true;
      continue;
    }
    if (!pastDashDash && t.startsWith("-")) {
      if (valueFlags?.has(t)) skipNext = true;
      continue;
    }
    out.push(t);
  }
  if (FIRST_OPERAND_NOT_PATH.has(verb)) out.shift();
  return out;
}

function basenameOf(token: string): string {
  return token.split("/").pop() || token;
}

// Fail-closed scan of an opaque wrapper's argument tokens: deny wrapped
// redirects (quote-internal `>` never surfaces as a structural redirect —
// `eval 'cat > transform.py'` is the exact #535 shape), wrapped shell
// interpreters (would dodge R8's verb-position check), and any word in
// WRAPPED_DENY_WORDS. Direct invocation is the documented recovery.
function scanOpaqueWrapperArgs(verb: string, args: string[]): string | null {
  for (const t of args) {
    if (t.includes(">")) {
      return deny(`'${verb}' wraps an output redirect — redirects may not be routed through wrappers`);
    }
    for (const w of t.split(/\s+/)) {
      if (WRAPPED_DENY_WORDS.has(w)) {
        return deny(
          `'${verb}' wraps '${w}' — invoke tools directly in their report/check form so each command can be evaluated on its own`,
        );
      }
      if (SHELL_INTERPRETERS.has(w)) {
        return deny(`'${verb}' wraps shell interpreter '${w}' — cannot be statically checked`);
      }
    }
  }
  return null;
}

// Per-segment report-only policy. Returns a deny reason or null.
export function analyzeReportOnlySegment(seg: Segment): string | null {
  // R1 — ANY output redirect (>, >|, >>) to a non-/tmp target. The general
  // guard's clobber rule exempts relative/cwd targets and `>>`; the
  // report-only contract exempts neither.
  for (const r of seg.redirects) {
    if (!r.target) continue;
    if (!underTmp(r.target)) {
      return deny(
        `output redirect '${r.op} ${r.target}' writes outside /tmp — this agent must not modify files`,
      );
    }
  }

  const tokens = stripEnvAssignments(seg.tokens);
  if (tokens.length === 0) return null;
  const verb = basenameOf(tokens[0]);

  // R2 — mutating flag anywhere in the segment, word-level so wrapper-quoted
  // payloads (`eval 'ruff check --fix .'`) are caught too.
  for (const t of tokens) {
    for (const w of t.split(/\s+/)) {
      const flag = w.includes("=") ? w.slice(0, w.indexOf("=")) : w;
      if (MUTATING_FLAGS.has(flag)) {
        return deny(`'${flag}' applies fixes/writes files`);
      }
      if (verb === "prettier" && (w === "-w" || w === "--write")) {
        return deny(`'prettier ${w}' rewrites files`);
      }
    }
  }

  // R2b — exec-wrappers and find: verb-position rules below cannot see a
  // mutation routed through `eval`/`sudo`/`xargs`/`find -exec` (the wrapper
  // is the verb). Without this, wrapped rm/mv would fall through to the
  // general guard's Rule 2 — whose deny text advertises
  // SKIP_DESTRUCTIVE_GUARD=1, and setting it would disarm the only check
  // blocking the command (the exact #535 sequence this profile closes).
  //
  // Two wrapper classes (closure-verification finding: a flat word-list
  // could not cover the conditional verbs — `ruff`/`black`/`cargo` are
  // legitimate directly but not resolvable inside an opaque payload —
  // without breaking `timeout 60 ruff check`):
  //   TRANSPARENT prefix wrappers (sudo/env/timeout/…): the wrapped command
  //   follows in argv — skip the wrapper's own flags/duration/assignments
  //   and RECURSE, so the full rule set (R2–R8) applies to the real verb.
  //   OPAQUE wrappers (eval/xargs/su/watch/…): the payload cannot be
  //   resolved to a command position — deny on any wrapped redirect,
  //   interpreter, or word in the wide WRAPPED_DENY_WORDS set. Recovery is
  //   documented in the message: invoke the tool directly (where the
  //   conditional rules can evaluate it).
  if (verb === "find") {
    if (tokens.includes("-delete")) {
      return deny(`'find -delete' removes files — the report-only contract forbids all deletion`);
    }
    const execIdx = tokens.findIndex((t) => t === "-exec" || t === "-execdir" || t === "-ok" || t === "-okdir");
    if (execIdx !== -1) {
      for (const t of tokens.slice(execIdx + 1)) {
        for (const w of t.split(/\s+/)) {
          if (WRAPPED_DENY_WORDS.has(w)) {
            return deny(`'find ${tokens[execIdx]} ${w}' runs a mutating command per file`);
          }
        }
      }
    }
  } else if (TRANSPARENT_PREFIX_WRAPPERS.has(verb)) {
    const rest = tokens.slice(1);
    let start = 0;
    // Skip only UNAMBIGUOUS wrapper arguments: env assignments (`K=V`) and
    // bare durations (timeout's `60`/`30s`). A dash-flag is NOT skippable —
    // flags like `sudo -u <user>` / `time -f <format>` consume a separate
    // value token, and skipping the flag alone would misparse the value as
    // the wrapped verb (`sudo -u www-data tee /path` → "verb" www-data →
    // zero-signal bypass; closure-verification finding 1b). Rather than
    // model each wrapper's flag grammar, a flagged transparent wrapper
    // falls back to the fail-closed opaque scan below.
    let sawFlag = false;
    while (start < rest.length) {
      if (rest[start].includes("=") || /^\d+[smhd]?$/.test(rest[start])) {
        start++;
        continue;
      }
      if (rest[start].startsWith("-")) sawFlag = true;
      break;
    }
    if (!sawFlag) {
      if (start < rest.length) {
        const inner = analyzeReportOnlySegment({
          tokens: rest.slice(start),
          readsInput: seg.readsInput,
          pipedInto: seg.pipedInto,
          redirects: [],
        });
        if (inner) return inner;
      }
      return null;
    }
    const opaque = scanOpaqueWrapperArgs(verb, rest);
    if (opaque) return opaque;
  } else if (WRAPPER_VERBS.has(verb)) {
    const opaque = scanOpaqueWrapperArgs(verb, tokens.slice(1));
    if (opaque) return opaque;
  }

  // R3 — in-place editors: sed/perl -i (any suffix form), gofmt/goimports/
  // shfmt -w.
  if (verb === "sed" || verb === "gsed" || verb === "perl") {
    for (const t of tokens.slice(1)) {
      if (t === "-i" || t.startsWith("-i.") || t.startsWith("--in-place") || (verb === "perl" && /^-[a-z]*i/.test(t))) {
        return deny(`'${verb} ${t}' edits files in place`);
      }
    }
  }
  if (SHORT_I_INPLACE_TOOLS.has(verb) && tokens.some((t) => t === "-i" || t.startsWith("--in-place"))) {
    return deny(`'${verb} -i' edits files in place`);
  }
  if ((verb === "gofmt" || verb === "goimports" || verb === "shfmt") && tokens.includes("-w")) {
    return deny(`'${verb} -w' rewrites files`);
  }

  // R4 — formatters that write by default, unless a check/diff flag is given.
  const checkFlags = DEFAULT_WRITE_FORMATTERS[verb];
  if (checkFlags && !tokens.some((t) => checkFlags.includes(t))) {
    return deny(`bare '${verb}' rewrites files — use ${checkFlags.join(" or ")}`);
  }
  if (verb === "ruff" && tokens[1] === "format" && !tokens.includes("--check") && !tokens.includes("--diff")) {
    return deny(`'ruff format' without --check/--diff rewrites files`);
  }
  if (verb === "dotnet" && tokens[1] === "format" && !tokens.includes("--verify-no-changes")) {
    return deny(`'dotnet format' without --verify-no-changes rewrites files`);
  }
  if (verb === "cargo" && tokens[1] === "fmt" && !tokens.includes("--check")) {
    return deny(`'cargo fmt' without --check rewrites files`);
  }
  if (verb === "terraform" && tokens[1] === "fmt" && !tokens.includes("-check") && !tokens.includes("--check")) {
    return deny(`'terraform fmt' without -check rewrites files`);
  }
  if (verb === "go" && tokens[1] === "fmt") {
    return deny(`'go fmt' rewrites files — use 'gofmt -l' to report`);
  }

  // R5 — file-mutation verbs: write targets must be under /tmp. This is
  // where the #535 relative in-cwd hole closes: `rm x`, `mv a b`,
  // `touch report.md`, `cat > transform.py` are all denied.
  if (verb === "dd") {
    const of = tokens.find((t) => t.startsWith("of="));
    if (of && !underTmp(of.slice(3))) {
      return deny(`'dd ${of}' writes outside /tmp`);
    }
    return null;
  }
  if (TMP_ONLY_ALL_OPERANDS.has(verb) || verb === "mv") {
    for (const p of pathOperands(tokens)) {
      if (!underTmp(p)) {
        return deny(`'${verb} ${p}' modifies a non-/tmp path`);
      }
    }
    return null;
  }
  if (TMP_ONLY_DEST_OPERAND.has(verb)) {
    const ops = pathOperands(tokens);
    const dest = ops[ops.length - 1];
    if (dest && !underTmp(dest)) {
      return deny(`'${verb} … ${dest}' writes to a non-/tmp path`);
    }
    return null;
  }

  // R6 — git: read-only subcommands only.
  if (verb === "git") {
    const sub = tokens.slice(1).find((t) => !t.startsWith("-"));
    if (sub && !GIT_READONLY.has(sub)) {
      return deny(`'git ${sub}' mutates repository state`);
    }
    return null;
  }

  // R7 — package managers: all verbs denied (install/run/exec).
  if (PKG_MANAGERS.has(verb)) {
    return deny(`'${verb}' installs packages or runs opaque scripts`);
  }
  if (verb === "cargo") {
    const sub = tokens.slice(1).find((t) => !t.startsWith("-")) ?? tokens[1];
    if (sub && !CARGO_READONLY.has(sub)) {
      return deny(`'cargo ${sub}' executes or writes build artifacts`);
    }
    return null;
  }
  if (verb === "npx" || verb === "pnpm-dlx" || verb === "bunx") {
    // The launcher itself is sanctioned; the wrapped tool's tokens were
    // already scanned by R2/R3/R4 above. Nothing further.
    return null;
  }

  // R8 — shell-interpreter bypass shapes (mirrors the general guard's Rule 1
  // so the profile holds even when SKIP_DESTRUCTIVE_GUARD=1 disables the
  // general rules).
  if (SHELL_INTERPRETERS.has(verb) && (seg.readsInput || seg.pipedInto || hasMinusC(tokens))) {
    return deny(
      `shell interpreter '${verb}' running a script from -c, stdin/file, or a pipeline sink cannot be statically checked`,
    );
  }

  return null;
}
