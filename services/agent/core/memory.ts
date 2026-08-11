import type { Memory } from "./seams.js";

// The only implementation shipped. Recall returning nothing is the seam's default,
// not a stub: a run never silently depends on what a backend happened to remember.
export const nullMemory: Memory = {
  recall: async () => [],
  remember: async () => {},
};
