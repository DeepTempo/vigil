import type { Memory } from "./seams.js";

// The only implementation shipped. Recall returning nothing is not a stub to be
// filled in later by whoever gets there first: it is the seam's default, so a
// run's behaviour never silently depends on what a memory backend happened to
// remember, and swapping one in is a wiring change rather than a rewrite.
export const nullMemory: Memory = {
  recall: async () => [],
  remember: async () => {},
};
