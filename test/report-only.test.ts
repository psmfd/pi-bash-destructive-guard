/**
 * bash-destructive-guard — report-only profile tests (#551, ADR-0091).
 *
 * Verifies that PI_GUARD_PROFILE=report-only (set by the subagent spawn
 * path from the wrapper's `guard-profile` frontmatter) turns the wrapper's
 * prose report-only contract into a mechanical gate: fix flags, in-place
 * editors, default-write formatters, in-cwd writes (including the #535
 * relative-path clobber shape), git/package-manager mutations, and
 * interpreter bypass shapes are denied; check/report invocations and /tmp
 * scratch writes pass. Also pins the override posture: the profile survives
 * SKIP_DESTRUCTIVE_GUARD=1, and deny messages advertise no self-service
 * override.
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

function makeCtx(calls?: NotifyCall[]) {
  return {
    cwd: process.cwd(),
    hasUI: calls !== undefined,
    ui: {
      notify(message: string, level: string) {
        calls?.push({ message, level });
      },
    },
  };
}

const mod = await import("../index.ts");

interface BlockResult {
  block: boolean;
  reason: string;
}

async function runProfiled(
  command: string,
  opts: { skip?: boolean } = {},
): Promise<BlockResult | undefined> {
  const prevProfile = process.env.PI_GUARD_PROFILE;
  const prevSkip = process.env.SKIP_DESTRUCTIVE_GUARD;
  process.env.PI_GUARD_PROFILE = "report-only";
  if (opts.skip) process.env.SKIP_DESTRUCTIVE_GUARD = "1";
  else delete process.env.SKIP_DESTRUCTIVE_GUARD;
  try {
    const pi = makePi();
    mod.default(pi as never);
    const handler = pi.handlers.tool_call?.[0];
    assert.ok(handler, "tool_call handler registered under the profile");
    const result = await handler({ toolName: "bash", input: { command } }, makeCtx());
    return result as BlockResult | undefined;
  } finally {
    if (prevProfile === undefined) delete process.env.PI_GUARD_PROFILE;
    else process.env.PI_GUARD_PROFILE = prevProfile;
    if (prevSkip === undefined) delete process.env.SKIP_DESTRUCTIVE_GUARD;
    else process.env.SKIP_DESTRUCTIVE_GUARD = prevSkip;
  }
}

// ---- DENY: the fix/mutation surface ----

const denied: Array<[string, string]> = [
  ["eslint --fix", "npx eslint --fix ."],
  ["ruff check --fix", "ruff check --fix src/"],
  ["ruff unsafe fixes", "ruff check --unsafe-fixes src/"],
  ["bare ruff format", "ruff format src/"],
  ["markdownlint --fix", "markdownlint-cli2 --fix '**/*.md'"],
  ["prettier --write", "prettier --write ."],
  ["prettier -w", "prettier -w src/app.ts"],
  ["bare dotnet format", "dotnet format ./proj.csproj"],
  ["bare black", "black src/"],
  ["bare isort", "isort src/"],
  ["bare rustfmt", "rustfmt src/main.rs"],
  ["bare cargo fmt", "cargo fmt"],
  ["gofmt -w", "gofmt -w main.go"],
  ["shfmt -w", "shfmt -w script.sh"],
  ["sed in-place", "sed -i 's/a/b/' file.txt"],
  ["sed in-place with suffix", "sed -i.bak 's/a/b/' file.txt"],
  ["perl in-place", "perl -pi -e 's/a/b/' file.txt"],
  ["relative clobber — the #535 shape", "cat > transform.py"],
  ["relative append", "echo done >> notes.md"],
  ["absolute non-tmp clobber", "cat > /etc/motd"],
  ["tee onto cwd file", "ruff check . | tee report.txt"],
  ["rm relative in cwd", "rm transform.py"],
  ["mv relative in cwd", "mv a.py b.py"],
  ["mv from tmp into cwd", "mv /tmp/fixed.py transform.py"],
  ["cp dest in cwd", "cp /tmp/fixed.py transform.py"],
  ["touch in cwd", "touch report.md"],
  ["git add", "git add -A"],
  ["git commit", "git commit -m fix"],
  ["git checkout file", "git checkout -- transform.py"],
  ["git stash", "git stash"],
  ["npm install", "npm install eslint"],
  ["npm run opaque script", "npm run fix"],
  ["pip install", "pip install ruff"],
  ["cargo build", "cargo build"],
  ["bash -c wrapper", "bash -c 'ruff check --fix .'"],
  ["fix flag inside eval payload", "eval 'ruff check --fix .'"],
  ["fix flag inside sudo wrapper", "sudo eslint --fix ."],
  ["piped into sh", "echo 'sed -i s/a/b/ f' | sh"],
  // Wrapper-routed mutations (code-review Criticals on the first cut: verb-
  // position rules alone let these through — R2b closes them).
  ["eval-wrapped sed -i", "eval 'sed -i s/x/y/ file.txt'"],
  ["sudo-wrapped tee onto cwd file", "sudo tee -a notes.md"],
  ["xargs chmod", "ls *.sh | xargs chmod 777"],
  ["eval-wrapped rm relative", "eval 'rm transform.py'"],
  ["sudo rm relative", "sudo rm transform.py"],
  ["xargs rm", "find . -name '*.orig' | xargs rm"],
  ["env-wrapped git commit", "env GIT_AUTHOR_NAME=x git commit -m fix"],
  ["find -delete relative root", "find . -name '*.pyc' -delete"],
  ["find -exec rm", "find . -type f -exec rm {} \\;"],
  ["find -execdir sed -i", "find src -name '*.py' -execdir sed -i s/a/b/ {} \\;"],
  // Security-review Error: quoted-payload redirect invisible to the
  // structural redirect scan — the exact #535 shape routed via a wrapper.
  ["eval-wrapped quoted redirect", "eval 'cat > transform.py'"],
  ["eval-wrapped quoted append", "eval 'echo done >> report.md'"],
  ["env-wrapped shell interpreter", "env sh -c 'echo x > f'"],
  ["xargs bash", "ls *.sh | xargs bash"],
  // Security-review Warnings: short-flag in-place editors, default-write
  // formatters, bun, mutable git subcommands.
  ["autopep8 -i", "autopep8 -i file.py"],
  ["yapf -i", "yapf -i file.py"],
  ["clang-format -i", "clang-format -i src/main.cpp"],
  ["bare terraform fmt", "terraform fmt"],
  ["go fmt", "go fmt ./..."],
  ["bare swiftformat", "swiftformat Sources/"],
  ["bun install", "bun install eslint"],
  ["bun run script", "bun run fix"],
  ["git branch delete", "git branch -d feature"],
  ["git config write", "git config user.name attacker"],
  ["git remote add", "git remote add origin https://example.com/x.git"],
  // Closure-verification vectors: conditional verbs hidden behind wrappers.
  ["sudo-wrapped bare rustfmt (transparent recursion)", "sudo rustfmt src/main.rs"],
  ["eval-wrapped bare black (opaque word-scan)", "eval 'black src/'"],
  ["xargs gofmt -w", "ls *.go | xargs -I{} gofmt -w {}"],
  ["eval-wrapped cargo publish", "eval 'cargo publish'"],
  ["find -exec black", "find . -name '*.py' -exec black {} \\;"],
  ["nested transparent wrappers", "sudo env RUST_LOG=off rustfmt src/main.rs"],
  // Closure-verification finding 1b: value-consuming wrapper flags must not
  // misparse the flag's value as the wrapped verb (flagged transparent
  // wrappers fall back to the opaque scan).
  ["sudo -u user tee outside /tmp", "sudo -u www-data tee /var/www/html/index.html"],
  ["sudo -u user rustfmt", "sudo -u root rustfmt src/main.rs"],
  ["env -u flag npm install", "env -u FOO npm install"],
  ["time -f format black", 'time -f "%e" black src/'],
  ["sudo -E rustfmt (flagged transparent falls closed)", "sudo -E rustfmt src/main.rs"],
  // ---- #798 / ADR-0112: parity with the general-guard fixes ----
  // Basename-normalized wrapped verb: `/bin/rm` must classify like `rm`.
  ["eval-wrapped absolute-path rm (basename)", "eval '/bin/rm transform.py'"],
  // Opaque-wrapped find -delete: `find` now in WRAPPED_DENY_WORDS.
  ["eval-wrapped find -delete (opaque find)", "eval 'find /etc -delete'"],
  // Formatter subcommand located as first non-flag token, not tokens[1], so a
  // glued global flag before the subcommand no longer slips past the deny.
  ["terraform glued global flag before fmt", "terraform -chdir=infra fmt"],
];

for (const [name, cmd] of denied) {
  test(`profile denies: ${name}`, async () => {
    const result = await runProfiled(cmd);
    assert.ok(result?.block, `expected deny for: ${cmd}`);
  });
}

// ---- ALLOW: the report/check surface ----

const allowed: Array<[string, string]> = [
  ["shellcheck", "shellcheck scripts/*.sh"],
  ["eslint report", "npx eslint ."],
  ["ruff check", "ruff check src/"],
  ["ruff format --check", "ruff format --check src/"],
  ["ruff format --diff", "ruff format --diff src/"],
  ["markdownlint report", "markdownlint-cli2 '**/*.md'"],
  ["prettier check", "prettier -c ."],
  ["dotnet format verify", "dotnet format --verify-no-changes ./proj.csproj"],
  ["black --check", "black --check src/"],
  ["isort --check-only", "isort --check-only src/"],
  ["cargo fmt --check", "cargo fmt -- --check"],
  ["cargo clippy", "cargo clippy"],
  ["yamllint", "yamllint -f parsable ."],
  ["git status", "git status --porcelain"],
  ["git diff", "git diff --stat"],
  ["git log", "git log --oneline -5"],
  ["grep", "grep -rn TODO src/"],
  ["cat read", "cat transform.py"],
  ["scratch clobber under /tmp", "ruff check . > /tmp/ruff-report.txt"],
  ["scratch append under /tmp", "echo done >> /tmp/lint.log"],
  ["tee under /tmp", "eslint . | tee /tmp/eslint.json"],
  ["rm under /tmp", "rm /tmp/scratch.txt"],
  ["cp source to /tmp scratch", "cp transform.py /tmp/check.py"],
  ["mkdir under /tmp", "mkdir /tmp/lint-scratch"],
  // Legitimate wrapper/find shapes stay allowed (R2b is word-targeted, not
  // a categorical wrapper ban).
  ["find without action", "find . -name '*.sh' -type f"],
  ["find -exec with read-only tool", "find . -name '*.sh' -exec shellcheck {} \\;"],
  ["xargs with read-only tool", "find . -name '*.sh' | xargs shellcheck"],
  ["timeout-wrapped linter", "timeout 60 ruff check src/"],
  // Value-consuming flags / non-path leading operands must not false-deny
  // (security-review Warning: the ADR-0082 false-denial mechanism).
  ["chmod mode operand under /tmp", "chmod 644 /tmp/scratch.txt"],
  ["chown owner operand under /tmp", "chown nobody /tmp/scratch.txt"],
  ["mkdir -m mode under /tmp", "mkdir -m 755 /tmp/lint-dir"],
  ["truncate -s size under /tmp", "truncate -s 0 /tmp/lint.log"],
  ["terraform fmt -check", "terraform fmt -check"],
  ["swiftformat --lint", "swiftformat --lint Sources/"],
  ["clang-format stdout mode", "clang-format src/main.cpp"],
  ["gofmt -l report mode", "gofmt -l src/"],
  // Transparent-wrapper recursion keeps check-mode invocations allowed —
  // the flat word-list alternative would have denied these.
  ["sudo-wrapped ruff check", "sudo ruff check src/"],
  ["env-wrapped shellcheck", "env TERM=dumb shellcheck script.sh"],
  ["timeout-wrapped rustfmt --check", "timeout 30 rustfmt --check src/main.rs"],
  // #798 / ADR-0112: check-mode with a glued global flag stays allowed — the
  // subcommand-locating fix must not over-deny the report form.
  ["terraform check with glued global flag", "terraform -chdir=infra fmt -check"],
];

for (const [name, cmd] of allowed) {
  test(`profile allows: ${name}`, async () => {
    const result = await runProfiled(cmd);
    assert.equal(result, undefined, `expected allow for: ${cmd}`);
  });
}

// ---- Override posture ----

test("profile survives SKIP_DESTRUCTIVE_GUARD=1 (deny still enforced)", async () => {
  const result = await runProfiled("ruff check --fix src/", { skip: true });
  assert.ok(result?.block, "profile must hold when the general guard is bypassed");
});

test("general-rule DENY is waived under SKIP while profile-clean command passes", async () => {
  // `rm /tmp/x` is allowed by BOTH rule sets; a general-only deny like an
  // out-of-safe-list rm is waived under SKIP, but the profile's own /tmp-only
  // rule still catches non-tmp targets — so use a shape only the general
  // rules would deny: none exists (profile is strictly stricter on writes).
  // Assert instead that a profile-clean read passes under SKIP.
  const result = await runProfiled("git status", { skip: true });
  assert.equal(result, undefined);
});

test("inline env-assignment prefix does not bypass the profile", async () => {
  const result = await runProfiled("SKIP_DESTRUCTIVE_GUARD=1 ruff check --fix src/");
  assert.ok(result?.block, "inline prefix must not defeat the profile");
});

test("deny message advertises no self-service override", async () => {
  const result = await runProfiled("sed -i 's/a/b/' file.txt");
  assert.ok(result?.block);
  assert.ok(!/SKIP_DESTRUCTIVE_GUARD/.test(result.reason), "must not name the skip env var");
  assert.ok(!/safe-paths\.conf/.test(result.reason), "must not point at the safe-paths conf");
  assert.match(result.reason, /report-only/);
});

test("no profile-reachable deny advertises an override (sweep of every denied shape)", async () => {
  for (const [name, cmd] of denied) {
    const result = await runProfiled(cmd);
    assert.ok(result?.block, `expected deny for: ${cmd}`);
    assert.ok(
      !/SKIP_DESTRUCTIVE_GUARD|bash-guard-safe-paths\.conf/.test(result.reason),
      `deny for '${name}' leaks an override advertisement:\n${result.reason}`,
    );
  }
});

test("general-rule denial under the profile is scrubbed of override advice", async () => {
  // A shape the profile itself does not deny but the general guard does
  // would be scrubbed by sanitizeGeneralDenyForProfile; construct one via a
  // wrapper the profile's word-scan misses but the general guard's
  // wrapsDestructive catches. No such shape exists by design (the profile's
  // verb-word set is a superset of rm|mv), so exercise the sanitizer
  // directly against the general guard's Rule 2 text.
  const { sanitizeGeneralDenyForProfile } = await import("../report-only.ts");
  const generalReason = `bash-destructive-guard: 'eval' wraps a destructive verb (rm|mv) — refusing for safety.

Suggested alternatives:
  - Invoke the destructive command directly.
  - If you must, set SKIP_DESTRUCTIVE_GUARD=1 for a one-off.
  - Or extend ~/.config/pi/bash-guard-safe-paths.conf.`;
  const scrubbed = sanitizeGeneralDenyForProfile(generalReason);
  assert.ok(!/SKIP_DESTRUCTIVE_GUARD|bash-guard-safe-paths\.conf/.test(scrubbed));
  assert.match(scrubbed, /report-only/);
});

test("without the profile env var, the fix surface is NOT gated (general guard scope only)", async () => {
  const prev = process.env.PI_GUARD_PROFILE;
  const prevSkip = process.env.SKIP_DESTRUCTIVE_GUARD;
  delete process.env.PI_GUARD_PROFILE;
  delete process.env.SKIP_DESTRUCTIVE_GUARD;
  try {
    const pi = makePi();
    mod.default(pi as never);
    const handler = pi.handlers.tool_call?.[0];
    assert.ok(handler);
    const result = await handler(
      { toolName: "bash", input: { command: "ruff check --fix src/" } },
      makeCtx(),
    );
    assert.equal(result, undefined, "fix flags are profile scope, not general-guard scope");
  } finally {
    if (prev !== undefined) process.env.PI_GUARD_PROFILE = prev;
    if (prevSkip !== undefined) process.env.SKIP_DESTRUCTIVE_GUARD = prevSkip;
  }
});

test("SKIP announce names the surviving profile", async () => {
  const prevProfile = process.env.PI_GUARD_PROFILE;
  const prevSkip = process.env.SKIP_DESTRUCTIVE_GUARD;
  process.env.PI_GUARD_PROFILE = "report-only";
  process.env.SKIP_DESTRUCTIVE_GUARD = "1";
  try {
    const pi = makePi();
    mod.default(pi as never);
    const calls: NotifyCall[] = [];
    const sessionStart = pi.handlers.session_start?.[0];
    assert.ok(sessionStart, "session_start announce registered");
    await sessionStart({}, makeCtx(calls));
    assert.equal(calls.length, 1);
    assert.match(calls[0].message, /report-only profile remains active/);
    assert.ok(pi.handlers.tool_call?.[0], "tool_call handler still installed");
  } finally {
    if (prevProfile === undefined) delete process.env.PI_GUARD_PROFILE;
    else process.env.PI_GUARD_PROFILE = prevProfile;
    if (prevSkip === undefined) delete process.env.SKIP_DESTRUCTIVE_GUARD;
    else process.env.SKIP_DESTRUCTIVE_GUARD = prevSkip;
  }
});
