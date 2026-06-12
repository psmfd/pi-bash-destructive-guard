/**
 * bash-destructive-guard — bypass + regression tests (#297).
 *
 * Verifies the hardened detection model closes the no-space-separator and
 * exec-wrapper bypasses (`rm;rm`, `;rm`, `rm&&rm`, `eval 'rm ...'`,
 * `xargs rm`, `sudo rm`, env-assignment prefixes, `$(rm ...)`) while NOT
 * regressing legitimate commands (relative rm, /tmp rm, flag clusters like
 * `grep -rm`, `rm` as a non-verb argument, safe compound chains).
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

function makeCtx() {
  return {
    cwd: process.cwd(),
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

async function run(command: string): Promise<BlockResult | undefined> {
  const prev = process.env.SKIP_DESTRUCTIVE_GUARD;
  delete process.env.SKIP_DESTRUCTIVE_GUARD;
  try {
    const pi = makePi();
    mod.default(pi as never);
    const handler = pi.handlers.tool_call?.[0];
    assert.ok(handler, "tool_call handler registered when not bypassed");
    const result = await handler(
      { toolName: "bash", input: { command } },
      makeCtx(),
    );
    return result as BlockResult | undefined;
  } finally {
    if (prev === undefined) delete process.env.SKIP_DESTRUCTIVE_GUARD;
    else process.env.SKIP_DESTRUCTIVE_GUARD = prev;
  }
}

// ---- DENY: no-space / glued compound separators (the core #297 bypass) ----

const denied = [
  ["rm;rm glued by semicolon", "rm;rm /etc/passwd"],
  ["leading semicolon", ";rm /etc/passwd"],
  ["rm&&rm glued by and", "rm&&rm /etc/passwd"],
  ["rm||rm glued by or", "rm||rm /etc/passwd"],
  ["spaced compound chain", "echo hi && rm /etc/passwd"],
  ["pipe into destructive", "echo /etc/passwd | rm /etc/passwd"],
  ["single & background separator", "echo hi & rm /etc/passwd"],
  ["newline-separated commands", "echo ok\nrm /etc/passwd"],
  ["subshell", "(rm /etc/passwd)"],
  ["process substitution", "cat <(rm /etc/passwd)"],
  ["escaped verb backslash", "\\rm /etc/passwd"],
  ["single-quoted verb", "'rm' /etc/passwd"],
  ["double-quoted verb", '"rm" /etc/passwd'],
  ["quoted absolute path", "rm '/etc/passwd'"],
  ["IFS-obfuscated separator", "rm$IFS/etc/passwd"],
  ["brace expansion with absolute paths", "rm {/etc/x,/etc/y}"],
  ["eval wraps rm", "eval 'rm /etc/passwd'"],
  ["xargs rm", "xargs rm"],
  ["find piped to xargs rm", "find . -name '*.log' | xargs rm"],
  ["sudo rm", "sudo rm /etc/passwd"],
  ["su -c rm wrapper", "su -c 'rm /etc/passwd'"],
  ["nested wrappers sudo timeout rm", "sudo timeout 5 rm /etc/passwd"],
  ["find -exec rm idiom", "find . -type f -exec rm -rf {} \\;"],
  ["exec builtin rm", "exec rm /etc/passwd"],
  ["absolute-path rm binary", "/bin/rm /etc/passwd"],
  ["absolute-path sudo wrapper", "/usr/bin/sudo rm /etc/passwd"],
  ["env wrapper rm", "env FOO=bar rm /etc/passwd"],
  ["leading env assignment then rm", "FOO=bar rm /etc/passwd"],
  ["quoted multi-word env value then rm", "FOO='bar baz' rm /etc/passwd"],
  ["two quoted env values then rm", "A='x y' B='p q' rm /etc/passwd"],
  ["line continuation splitting verb", "r\\\nm /etc/passwd"],
  ["here-string into bash", "bash<<<'rm /etc/passwd'"],
  ["heredoc script into bash", "bash <<EOF\nrm /etc/passwd\nEOF"],
  ["nohup rm", "nohup rm /etc/passwd"],
  ["command wrapper rm", "command rm /etc/passwd"],
  ["time wrapper rm", "time rm /etc/passwd"],
  ["timeout wrapper rm", "timeout 5 rm /etc/passwd"],
  ["command substitution rm to unsafe path", "echo $(rm /etc/passwd)"],
  ["backtick substitution rm", "echo `rm /etc/passwd`"],
  ["plain absolute rm outside safe", "rm /etc/passwd"],
  ["rm -rf root", "rm -rf /"],
  ["mv out of safe", "mv /etc/passwd /var/tmp/x"],
  ["sh -c rm", "sh -c 'rm /etc/passwd'"],
] as const;

for (const [name, cmd] of denied) {
  test(`DENY: ${name} — ${cmd}`, async () => {
    const r = await run(cmd);
    assert.ok(r && r.block === true, `expected block for: ${cmd}`);
    assert.match(r.reason, /bash-destructive-guard:/);
  });
}

// ---- ALLOW: legitimate commands must not regress ----

const allowed = [
  ["relative rm", "rm foo.txt"],
  ["rm under /tmp", "rm /tmp/scratch"],
  ["mv relative", "mv a.txt b.txt"],
  ["no destructive verb", "ls -la /etc"],
  ["rm as echo argument (no evasion)", "echo rm"],
  ["git rm subcommand (out of scope, no evasion)", "git rm foo.txt"],
  ["grep -rm flag cluster piped", "grep -rm 3 pattern file | cat"],
  ["safe compound with relative rm", "echo a && rm relative.txt"],
  ["substring words in compound (alarm/format)", "echo format && echo alarm"],
  // False-positive regressions the old broad net wrongly blocked (#297 review):
  ["pipe to grep for rm", "git log | grep rm"],
  ["which rm then echo", "which rm && echo ok"],
  ["man rm paged", "man rm | less"],
  ["legit process substitution", "diff <(sort a) <(sort b)"],
  // Path component literally named rm/mv under a wrapper must NOT trip (round 2):
  ["wrapper with rm as path component", "sudo ls /home/rm/file"],
  ["wrapper listing mv-named file", "time cat /var/log/mv.log"],
  ["find without destructive verb", "find . -name '*.log'"],
  // Destructive verb + absolute path as quoted DATA, not a command (round 2):
  ["echo of literal text with rm", 'echo "; rm /etc/passwd"'],
  // Command substitution targeting a SAFE path is now validated, not blocked:
  ["command substitution rm to /tmp", "echo $(rm /tmp/scratch)"],
  // Heredoc body is data, not an executed command (cat, not a shell):
  ["rm inside data heredoc body", "cat <<EOF\nrm /etc/passwd\nEOF"],
] as const;

for (const [name, cmd] of allowed) {
  test(`ALLOW: ${name} — ${cmd}`, async () => {
    const r = await run(cmd);
    assert.equal(r, undefined, `expected allow (undefined) for: ${cmd}`);
  });
}
