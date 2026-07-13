/**
 * bash-destructive-guard — AST second-pass tests (#506, ADR-0100).
 *
 * Hermetic: PI_BASH_PARSER_BIN points at a tiny fake parser that emits canned
 * JSON (or exits non-zero), so the tests never depend on the vendored binary.
 * Unit tests drive astSecondPass() directly; integration tests drive the full
 * tool_call handler (index.ts) to prove the AST segments are policed by BOTH
 * the general and the report-only profiles.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { astPassApplies, astSecondPass, initAstConfig } from "../ast-second-pass.ts";

// Build a fake parser executable. `body` is the shell after the shebang.
function fakeParser(body: string): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "bdg-ast-"));
  const path = join(dir, "fake-parser");
  writeFileSync(path, `#!/usr/bin/env bash\n${body}\n`);
  chmodSync(path, 0o755);
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

// A fake that emits one segment with the given tokens.
function emitSegment(tokens: string[]): { path: string; cleanup: () => void } {
  const json = JSON.stringify([{ tokens, readsInput: false, pipedInto: false, redirects: [] }]);
  return fakeParser(`cat >/dev/null; printf '%s' '${json}'`);
}

test("astPassApplies triggers only on substitution / ANSI-C shapes", () => {
  assert.equal(astPassApplies("$'\\x72m' -rf /x"), true);
  assert.equal(astPassApplies("r$(true)m -rf /x"), true);
  assert.equal(astPassApplies("echo `id`"), true);
  assert.equal(astPassApplies("rm -rf /x"), false);
  assert.equal(astPassApplies("ls | grep foo"), false, "bare pipe is handled by the hand-lexer");
});

test("non-triggering command returns none without spawning", async () => {
  const f = emitSegment(["rm", "/x"]);
  try {
    const r = await astSecondPass("rm -rf /x", { strict: false, binPath: f.path });
    assert.deepEqual(r, { kind: "none" });
  } finally {
    f.cleanup();
  }
});

test("triggered command returns the parsed segments", async () => {
  const f = emitSegment(["rm", "-rf", "/etc"]);
  try {
    const r = await astSecondPass("$'\\x72m' -rf /etc", { strict: false, binPath: f.path });
    assert.equal(r.kind, "segments");
    if (r.kind === "segments") assert.deepEqual(r.segments[0].tokens, ["rm", "-rf", "/etc"]);
  } finally {
    f.cleanup();
  }
});

test("binary unavailable: none by default, deny under strict", async () => {
  assert.deepEqual(await astSecondPass("r$(true)m /x", { strict: false, binPath: null }), { kind: "none" });
  const strict = await astSecondPass("r$(true)m /x", { strict: true, binPath: null });
  assert.equal(strict.kind, "deny");
});

test("parse error: none by default, deny under strict", async () => {
  const f = fakeParser("cat >/dev/null; exit 1");
  try {
    assert.deepEqual(await astSecondPass("$(bad", { strict: false, binPath: f.path }), { kind: "none" });
    const strict = await astSecondPass("$(bad", { strict: true, binPath: f.path });
    assert.equal(strict.kind, "deny");
  } finally {
    f.cleanup();
  }
});

test("malformed / non-array JSON is a parse error", async () => {
  for (const body of ["cat >/dev/null; printf 'not json'", `cat >/dev/null; printf '{"not":"array"}'`]) {
    const f = fakeParser(body);
    try {
      assert.deepEqual(await astSecondPass("$(x)", { strict: false, binPath: f.path }), { kind: "none" });
    } finally {
      f.cleanup();
    }
  }
});

test("strict deny messages never name the PI_BASH_GUARD_AST_STRICT override (ADR-0091/#535)", async () => {
  const r = await astSecondPass("$(x)", { strict: true, binPath: null });
  assert.equal(r.kind, "deny");
  if (r.kind === "deny") assert.doesNotMatch(r.reason, /PI_BASH_GUARD_AST_STRICT|unset/);
});

test("malformed-but-array segment elements are coerced, not thrown", async () => {
  // non-string tokens + a null redirect must not crash the coercion.
  const f = fakeParser(`cat >/dev/null; printf '%s' '[{"tokens":["rm",42,null],"redirects":[null,{"op":">","target":"/x"}]}]'`);
  try {
    const r = await astSecondPass("$(x)", { strict: false, binPath: f.path });
    assert.equal(r.kind, "segments");
    if (r.kind === "segments") {
      assert.deepEqual(r.segments[0].tokens, ["rm"], "non-string tokens dropped");
      assert.deepEqual(r.segments[0].redirects, [{ op: ">", target: "/x" }], "null redirect dropped");
    }
  } finally {
    f.cleanup();
  }
});

test("initAstConfig captures strict + path from the environment", () => {
  const prevStrict = process.env.PI_BASH_GUARD_AST_STRICT;
  const prevBin = process.env.PI_BASH_PARSER_BIN;
  try {
    process.env.PI_BASH_GUARD_AST_STRICT = "1";
    process.env.PI_BASH_PARSER_BIN = "/nonexistent";
    const cfg = initAstConfig();
    assert.equal(cfg.strict, true);
    assert.equal(cfg.binPath, null, "nonexistent override resolves to null, no fallback");
  } finally {
    if (prevStrict === undefined) delete process.env.PI_BASH_GUARD_AST_STRICT;
    else process.env.PI_BASH_GUARD_AST_STRICT = prevStrict;
    if (prevBin === undefined) delete process.env.PI_BASH_PARSER_BIN;
    else process.env.PI_BASH_PARSER_BIN = prevBin;
  }
});

// --- Integration via the full tool_call handler --------------------------

type Handler = (event: unknown, ctx: unknown) => unknown;
interface FakePi {
  on(name: string, handler: Handler): void;
  handlers: Record<string, Handler[]>;
}
function makePi(): FakePi {
  const handlers: Record<string, Handler[]> = {};
  return { on(name, h) { (handlers[name] ??= []).push(h); }, handlers };
}
function makeCtx() {
  return { cwd: process.cwd(), hasUI: false, ui: { notify() {} } };
}
const mod = await import("../index.ts");
interface BlockResult { block: boolean; reason: string }

// Runs the handler with the given env captured at load (initAstConfig +
// isReportOnlyProfileActive read env when mod.default runs).
async function runHandler(
  command: string,
  env: Record<string, string | undefined>,
): Promise<BlockResult | undefined> {
  const keys = ["PI_GUARD_PROFILE", "PI_BASH_PARSER_BIN", "SKIP_DESTRUCTIVE_GUARD", "PI_BASH_GUARD_AST_STRICT"];
  const prev: Record<string, string | undefined> = {};
  for (const k of keys) {
    prev[k] = process.env[k];
    if (env[k] === undefined) delete process.env[k];
    else process.env[k] = env[k];
  }
  try {
    const pi = makePi();
    mod.default(pi as never);
    const handler = pi.handlers.tool_call?.[0];
    assert.ok(handler, "tool_call handler registered");
    return (await handler({ toolName: "bash", input: { command } }, makeCtx())) as BlockResult | undefined;
  } finally {
    for (const k of keys) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
  }
}

test("integration: AST pass blocks a general-policy hit the hand-lexer missed", async () => {
  const f = emitSegment(["rm", "-rf", "/etc/foo"]);
  try {
    const r = await runHandler("$'\\x72m' -rf /etc/foo", { PI_BASH_PARSER_BIN: f.path });
    assert.ok(r?.block, "ANSI-C-obfuscated rm on an absolute path is blocked via the AST pass");
  } finally {
    f.cleanup();
  }
});

test("integration: AST pass extends the REPORT-ONLY profile (the #506 gap)", async () => {
  // A report-only-blockable segment (in-place editor) that the hand-lexer's
  // profile check would miss when ANSI-C-obfuscated.
  const f = emitSegment(["sed", "-i", "s/x/y/", "notes.md"]);
  try {
    const r = await runHandler("$'\\x73ed' -i s/x/y/ notes.md", {
      PI_GUARD_PROFILE: "report-only",
      PI_BASH_PARSER_BIN: f.path,
    });
    assert.ok(r?.block, "report-only profile blocks the AST-discovered in-place editor");
  } finally {
    f.cleanup();
  }
});

test("integration: additive default allows when the binary is absent", async () => {
  const r = await runHandler("echo $(date)", { PI_BASH_PARSER_BIN: "/nonexistent" });
  assert.equal(r, undefined, "binary absent + additive default → allow");
});
