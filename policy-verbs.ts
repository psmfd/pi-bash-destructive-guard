/**
 * bash-destructive-guard/policy-verbs.ts — verb classification sets shared
 * by the general guard (index.ts) and the report-only profile
 * (report-only.ts). Extracted so the profile can mirror the general guard's
 * wrapper handling without an import cycle (index.ts imports report-only.ts).
 */

export const SHELL_INTERPRETERS = new Set(["bash", "sh", "dash", "zsh", "ksh", "busybox"]);

// Exec-wrappers that run another command and would otherwise hide a leading
// verb from command-position classification. Argument grammars are not
// parsed; consumers word-scan the remaining tokens and fail closed.
export const WRAPPER_VERBS = new Set([
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
