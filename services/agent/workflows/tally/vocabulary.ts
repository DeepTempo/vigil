// The throwaway workflow of #592. Two verbs, one tool, a count, and an ending.
// It exists so the harness boundary is first exercised by something that is not
// a real domain: driven first by the hunt, the boundary would get drawn around
// hunting and nobody would find out until the second workflow landed.

export const TALLY_VERBS = ["TALLY", "HALT"] as const;
export type TallyVerb = (typeof TALLY_VERBS)[number];

export interface TallyPayload {
  verb: TallyVerb;
  count: number;
  note: string;
}

// The workflow's own closed kind set, which the ledger repository is generic
// over. The harness never imports this, and that is what makes ADR-0002's
// domain-free requirement checkable rather than merely asserted.
export type TallyKinds = { tally: TallyPayload };

export const TALLY_SCHEMA: Record<string, unknown> = {
  type: "object",
  additionalProperties: false,
  required: ["verb", "note"],
  properties: {
    verb: { type: "string", enum: [...TALLY_VERBS] },
    note: { type: "string", maxLength: 200 },
  },
};

export const SYSTEM = [
  "You keep a running count and nothing else.",
  "Call bump to add to it. When the count has reached its target, emit HALT.",
  "Emit TALLY to keep going. Both verbs require a one-line note.",
].join("\n");
