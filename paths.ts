/**
 * bash-destructive-guard/paths.ts — path canonicalization shared by the
 * general guard (index.ts) and the report-only profile (report-only.ts).
 */

import { realpathSync } from "node:fs";
import { basename, dirname, join, normalize } from "node:path";

// Canonicalize a path for safe-list comparison: resolve symlinks and
// normalize. A target that does not exist yet (new-file clobber, `mv` dest)
// is resolved via its nearest existing ancestor with the non-existent tail
// re-joined, so `/var/folders/…/new.txt` under a symlinked ancestor still
// canonicalizes consistently with a safe-list entry recorded in canonical
// form (#554 Observation B: macOS `/var` → `/private/var` caused false
// denies for paths genuinely inside the safe cwd). On total resolution
// failure the normalized input is returned — identical to the pre-fix
// behavior modulo `.`/`//` cleanup, preserving the guard's posture.
export function canonicalize(p: string): string {
  let head = normalize(p);
  let tail = "";
  for (;;) {
    try {
      const resolved = realpathSync(head);
      return tail ? join(resolved, tail) : resolved;
    } catch {
      const parent = dirname(head);
      if (parent === head) return normalize(p);
      tail = tail ? join(basename(head), tail) : basename(head);
      head = parent;
    }
  }
}
