/**
 * bash-destructive-guard — session-wide-bypass announcement tests (#258).
 *
 * Verifies the ADR-0022 § Q5 "override cannot be silent" contract: when
 * SKIP_DESTRUCTIVE_GUARD=1 is set, the extension installs a session_start
 * handler that emits a `warning`-level notify naming the bypass env var,
 * and does NOT install a tool_call handler. When ctx.hasUI is false (e.g.
 * `pi -p` non-UI mode), the notify call is suppressed cleanly.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

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

interface NotifyCall {
  message: string;
  level: string;
}

function makeCtx(hasUI: boolean): { ctx: unknown; calls: NotifyCall[] } {
  const calls: NotifyCall[] = [];
  const ctx = {
    cwd: process.cwd(),
    hasUI,
    ui: {
      notify(message: string, level: string) {
        calls.push({ message, level });
      },
    },
  };
  return { ctx, calls };
}

const mod = await import("../index.ts");

test("SKIP_DESTRUCTIVE_GUARD=1 + UI: announces bypass via warning notify on session_start", () => {
  const prev = process.env.SKIP_DESTRUCTIVE_GUARD;
  process.env.SKIP_DESTRUCTIVE_GUARD = "1";
  try {
    const pi = makePi();
    mod.default(pi as never);

    assert.equal(pi.handlers.session_start?.length, 1, "session_start handler registered");
    assert.equal(pi.handlers.tool_call, undefined, "tool_call handler NOT registered");

    const { ctx, calls } = makeCtx(true);
    pi.handlers.session_start[0]({}, ctx);

    assert.equal(calls.length, 1);
    assert.match(
      calls[0].message,
      /bash-destructive-guard: bypassed via SKIP_DESTRUCTIVE_GUARD=1/,
    );
    assert.equal(calls[0].level, "warning");
  } finally {
    if (prev === undefined) delete process.env.SKIP_DESTRUCTIVE_GUARD;
    else process.env.SKIP_DESTRUCTIVE_GUARD = prev;
  }
});

test("SKIP_DESTRUCTIVE_GUARD=1 + no UI: session_start handler is a clean no-op", () => {
  const prev = process.env.SKIP_DESTRUCTIVE_GUARD;
  process.env.SKIP_DESTRUCTIVE_GUARD = "1";
  try {
    const pi = makePi();
    mod.default(pi as never);

    const { ctx, calls } = makeCtx(false);
    pi.handlers.session_start[0]({}, ctx);

    assert.equal(calls.length, 0);
  } finally {
    if (prev === undefined) delete process.env.SKIP_DESTRUCTIVE_GUARD;
    else process.env.SKIP_DESTRUCTIVE_GUARD = prev;
  }
});

test("SKIP_DESTRUCTIVE_GUARD unset: registers tool_call, no session_start announce", () => {
  const prev = process.env.SKIP_DESTRUCTIVE_GUARD;
  delete process.env.SKIP_DESTRUCTIVE_GUARD;
  try {
    const pi = makePi();
    mod.default(pi as never);

    assert.equal(pi.handlers.tool_call?.length, 1, "tool_call handler registered");
    assert.equal(pi.handlers.session_start, undefined, "no session_start announce");
  } finally {
    if (prev !== undefined) process.env.SKIP_DESTRUCTIVE_GUARD = prev;
  }
});
