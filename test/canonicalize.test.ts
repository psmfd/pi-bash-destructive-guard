/**
 * bash-destructive-guard — safe-path canonicalization tests (#554).
 *
 * Verifies Observation B's fix: safe-list entries and absolute target paths
 * are canonicalized (symlinks resolved, `.`/`//` normalized) before the
 * prefix comparison, so a symlinked spelling of a path genuinely inside the
 * safe cwd (macOS `/var/…` vs `/private/var/…`) is no longer falsely denied
 * — including targets that do not exist yet (new-file clobber, `mv` dest),
 * which resolve via their nearest existing ancestor. Also pins the
 * regression direction: paths genuinely outside the safe list stay denied
 * even when addressed through a symlink.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

type Handler = (event: unknown, ctx: unknown) => unknown;

interface FakePi {
  on(name: string, handler: Handler): void;
  handlers: Record<string, Handler[]>;
}

function makePi(): FakePi {
  const handlers: Record<string, Handler[]> = {};
  return {
    on(name, handler) {
      (handlers[name] ??= []).push(handler);
    },
    handlers,
  };
}

function makeCtx(cwd: string) {
  return {
    cwd,
    hasUI: false,
    ui: {
      notify() {
        /* no-op */
      },
    },
  };
}

const mod = await import("../index.ts");

interface BlockResult {
  block: boolean;
  reason: string;
}

async function run(command: string, cwd: string): Promise<BlockResult | undefined> {
  const prev = process.env.SKIP_DESTRUCTIVE_GUARD;
  delete process.env.SKIP_DESTRUCTIVE_GUARD;
  try {
    const pi = makePi();
    mod.default(pi as never);
    const handler = pi.handlers.tool_call?.[0];
    assert.ok(handler, "tool_call handler registered when not bypassed");
    const result = await handler({ toolName: "bash", input: { command } }, makeCtx(cwd));
    return result as BlockResult | undefined;
  } finally {
    if (prev === undefined) delete process.env.SKIP_DESTRUCTIVE_GUARD;
    else process.env.SKIP_DESTRUCTIVE_GUARD = prev;
  }
}

// Fixture: a real project dir, a symlinked spelling of it, and an unrelated
// outside dir. The fixture root deliberately lives under the TEST PROCESS
// cwd (the repo tree), NOT under os.tmpdir(): on Linux tmpdir() IS /tmp,
// which sits on the guard's built-in safe list, so tmpdir-rooted fixtures
// would make every DENY assertion vacuously pass the /tmp entry instead of
// exercising the cwd entry. Each run() call passes an explicit ctx.cwd
// (realProject or linkedProject), so the repo tree itself is never on the
// safe list during a check. macOS still exercises the production #554 shape
// end-to-end via the explicit symlink fixture on any platform.
let fixtureRoot: string;
let realProject: string; // canonical form
let linkedProject: string; // symlinked spelling of realProject
let outsideDir: string; // canonical, outside cwd and /tmp

before(() => {
  fixtureRoot = realpathSync(mkdtempSync(join(process.cwd(), ".bdg554-fixture-")));
  realProject = join(fixtureRoot, "real");
  mkdirSync(realProject);
  linkedProject = join(fixtureRoot, "link");
  symlinkSync(realProject, linkedProject);
  writeFileSync(join(realProject, "file.txt"), "x\n");
  mkdirSync(join(realProject, "sub"));
  outsideDir = join(fixtureRoot, "outside");
  mkdirSync(outsideDir);
  writeFileSync(join(outsideDir, "victim.txt"), "x\n");
});

after(() => {
  try {
    rmSync(fixtureRoot, { recursive: true, force: true });
  } catch {
    /* best-effort cleanup */
  }
});

test("symlinked spelling of a file inside cwd is allowed (the #554 false-deny)", async () => {
  const result = await run(`rm ${join(linkedProject, "file.txt")}`, realProject);
  assert.equal(result, undefined);
});

test("canonical spelling while cwd is the symlinked form is allowed", async () => {
  const result = await run(`rm ${join(realProject, "file.txt")}`, linkedProject);
  assert.equal(result, undefined);
});

test("nonexistent target under the symlinked cwd resolves via nearest ancestor", async () => {
  const result = await run(`rm ${join(linkedProject, "sub", "not-yet-created.txt")}`, realProject);
  assert.equal(result, undefined);
});

test("output-redirect clobber via the symlinked spelling is allowed", async () => {
  const result = await run(`cat > ${join(linkedProject, "out.txt")}`, realProject);
  assert.equal(result, undefined);
});

test("non-normalized ./ spelling inside cwd is allowed", async () => {
  const result = await run(`rm ${realProject}/./file.txt`, realProject);
  assert.equal(result, undefined);
});

test("path genuinely outside the safe list is still denied", async () => {
  const result = await run(`rm ${join(outsideDir, "victim.txt")}`, realProject);
  assert.ok(result?.block, "expected deny for out-of-safe-list path");
});

test("clobber genuinely outside the safe list is still denied", async () => {
  const result = await run(`cat > ${join(outsideDir, "out.txt")}`, realProject);
  assert.ok(result?.block, "expected deny for out-of-safe-list clobber");
});

test("symlink INTO an out-of-safe-list dir is denied (canonical form escapes)", async () => {
  const escapeLink = join(realProject, "escape");
  symlinkSync(outsideDir, escapeLink);
  try {
    const result = await run(`rm ${join(escapeLink, "victim.txt")}`, realProject);
    assert.ok(
      result?.block,
      "expected deny: canonical form of the target is outside the safe list",
    );
  } finally {
    rmSync(escapeLink, { force: true });
  }
});
