/**
 * ast-second-pass.ts — mvdan/sh-backed AST second opinion for
 * bash-destructive-guard (pi_config #506, ADR-0100).
 *
 * The TypeScript hand-lexer (shared/shell-lex.ts) cannot soundly resolve a few
 * shapes: ANSI-C quoting ($'\x72m'), value-glued substitutions, and nested
 * command substitution as distinct command positions. When a command contains
 * one of those shapes, this module spawns the vendored `pi-bash-parser` binary
 * (agent/vendor/bash-parser/, installed by setup.sh) to get a real parse and
 * returns its command-position segments; the CALLER (index.ts) re-applies the
 * guard's OWN policy (both the general and report-only profiles). Parsing here,
 * policy in the guard.
 *
 * POSTURE (the security-sensitive decision — see ADR-0100 § Considered Options):
 *   ADDITIVE defense-in-depth, not a replacement for the hand-lexer and not the
 *   sound boundary (that is #507's OS sandbox). By DEFAULT it only ever lets the
 *   caller ADD a denial — a command the hand-lexer allowed is blocked only when
 *   the binary is present, the parse succeeds, and the guard's policy fires on
 *   an AST segment. Binary-absent and parse-failure yield `none` (defer to the
 *   hand-lexer), because denying every command that merely contains `$(` because
 *   a helper binary is missing would break ordinary agent use (`echo "$(date)"`)
 *   and false-positive denials erode the trust the guard depends on.
 *
 *   PI_BASH_GUARD_AST_STRICT=1 opts into deny-by-default: a triggered command is
 *   denied (`deny`) when the binary is unavailable or the parse fails.
 *
 * Config (strict mode + resolved binary path) is captured ONCE via
 * initAstConfig(), mirroring how index.ts captures skipGeneral/profileActive at
 * load time so an in-session env mutation cannot downgrade strict->additive or
 * repoint the binary mid-session (index.ts § "read at load time").
 *
 * The trigger is a cheap syntactic check, so the common case never spawns.
 */

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import type { Segment } from "./shared/shell-lex.ts";

// Only these shapes are worth a real parse — the hand-lexer already handles
// pipes, redirects, ordinary quoting, and empty-glued substitution.
const AST_TRIGGER_RE = /\$'|\$\(|`/;

// Bound the parser's stdout so a misbehaving binary cannot pressure host memory
// within the timeout window (secrets-guard uses the same 512 KB idiom).
const MAX_OUTPUT_BYTES = 512 * 1024;
const SPAWN_TIMEOUT_MS = 2000;

export function astPassApplies(command: string): boolean {
  return AST_TRIGGER_RE.test(command);
}

/** Posture config, captured once at extension load (see module header). */
export interface AstConfig {
  strict: boolean;
  binPath: string | null;
}

// Resolve the vendored binary. PI_BASH_PARSER_BIN, when set, is authoritative
// (used if it exists, else treated as unavailable — no silent fallback); when
// unset, setup.sh's ~/.local/bin/pi-bash-parser is used.
function resolveParserPath(): string | null {
  const override = process.env.PI_BASH_PARSER_BIN;
  if (override !== undefined) return existsSync(override) ? override : null;
  const local = join(homedir(), ".local", "bin", "pi-bash-parser");
  return existsSync(local) ? local : null;
}

/** Read strict mode + resolve the binary ONCE. Call at extension load. */
export function initAstConfig(): AstConfig {
  return {
    strict: process.env.PI_BASH_GUARD_AST_STRICT === "1",
    binPath: resolveParserPath(),
  };
}

interface AstSegment {
  tokens?: unknown;
  readsInput?: unknown;
  pipedInto?: unknown;
  redirects?: unknown;
}

// Coerce one parser segment to a guard Segment, defensively — a malformed
// (array-shaped but wrong-typed) payload must not throw into analyzeSegment.
function coerceSegment(s: AstSegment): Segment {
  const tokens = Array.isArray(s.tokens) ? s.tokens.filter((t): t is string => typeof t === "string") : [];
  const redirects = Array.isArray(s.redirects)
    ? s.redirects
        .filter((r): r is Record<string, unknown> => !!r && typeof r === "object")
        .map((r) => ({
          op: typeof r.op === "string" ? r.op : "",
          target: typeof r.target === "string" ? r.target : "",
        }))
    : [];
  return { tokens, readsInput: !!s.readsInput, pipedInto: !!s.pipedInto, redirects };
}

/** Spawn result: parsed segments, a parse error, or the binary being absent. */
type RunResult =
  | { kind: "segments"; segments: Segment[] }
  | { kind: "parse-error" }
  | { kind: "unavailable" };

function runParser(bin: string, command: string): Promise<RunResult> {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(bin, [], { stdio: ["pipe", "pipe", "ignore"] });
    } catch {
      resolve({ kind: "unavailable" });
      return;
    }
    let out = "";
    let overflow = false;
    let settled = false;
    const done = (r: RunResult) => {
      if (settled) return;
      settled = true;
      resolve(r);
    };
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* ignore */
      }
      done({ kind: "unavailable" });
    }, SPAWN_TIMEOUT_MS);
    child.on("error", () => {
      clearTimeout(timer);
      done({ kind: "unavailable" });
    });
    // Both streams need an error handler — an unhandled stream 'error' throws by
    // default and would crash the extension host, not just fail this check.
    child.stdout.on("error", () => {
      clearTimeout(timer);
      done({ kind: "unavailable" });
    });
    child.stdout.on("data", (d) => {
      if (overflow) return;
      out += String(d);
      if (out.length > MAX_OUTPUT_BYTES) {
        overflow = true;
        try {
          child.kill("SIGKILL");
        } catch {
          /* ignore */
        }
        clearTimeout(timer);
        done({ kind: "unavailable" });
      }
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (overflow) return; // already settled
      if (code !== 0) {
        done({ kind: "parse-error" });
        return;
      }
      try {
        const raw = JSON.parse(out);
        if (!Array.isArray(raw)) {
          done({ kind: "parse-error" });
          return;
        }
        done({ kind: "segments", segments: raw.map((s) => coerceSegment(s as AstSegment)) });
      } catch {
        done({ kind: "parse-error" });
      }
    });
    child.stdin.on("error", () => {
      /* EPIPE if the child exits early — handled via close/error */
    });
    child.stdin.end(command);
  });
}

/** What the caller should do after the AST pass. */
export type AstResult =
  | { kind: "none" } // nothing to add (no trigger, or additive fail-open)
  | { kind: "deny"; reason: string } // strict-mode meta denial (sanitize under profile)
  | { kind: "segments"; segments: Segment[] }; // apply the guard's policies to these

/**
 * Run the AST second pass on a command the hand-lexer already ALLOWED. Returns
 * segments for the caller to police, a meta `deny` (strict mode only), or
 * `none` to defer to the hand-lexer's allow verdict.
 */
export async function astSecondPass(command: string, cfg: AstConfig): Promise<AstResult> {
  if (!astPassApplies(command)) return { kind: "none" };

  if (!cfg.binPath) {
    if (cfg.strict) {
      return {
        kind: "deny",
        reason:
          "bash-destructive-guard: this command uses substitution/ANSI-C quoting that requires the AST second opinion, but the parser is not installed and strict mode is on — refusing.",
      };
    }
    return { kind: "none" };
  }

  const result = await runParser(cfg.binPath, command);
  if (result.kind === "unavailable") {
    return cfg.strict
      ? { kind: "deny", reason: "bash-destructive-guard: the AST second opinion could not run and strict mode is on — refusing the command." }
      : { kind: "none" };
  }
  if (result.kind === "parse-error") {
    return cfg.strict
      ? { kind: "deny", reason: "bash-destructive-guard: the parser could not parse this command and strict mode is on — refusing an un-analyzable command." }
      : { kind: "none" };
  }
  return { kind: "segments", segments: result.segments };
}
