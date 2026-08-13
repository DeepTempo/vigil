import type { Memory } from "./seams.js";

// Notes from somewhere the caller named, not a search over everything: what a
// finished run carries forward is its own workflow's to say.
export type Notes = (limit: number) => Promise<readonly string[]>;

// The only implementation shipped. Recall returning nothing is the seam's default,
// not a stub: a run never silently depends on what a backend happened to remember.
export const nullMemory: Memory = {
  recall: async () => [],
  remember: async () => {},
};

// The cue is ignored because the caller already answered what to recall from.
// Remembering is still nothing: recall reads a run that is over.
export function recalling(notes: Notes): Memory {
  return { recall: async (_cue, limit) => notes(limit), remember: async () => {} };
}
