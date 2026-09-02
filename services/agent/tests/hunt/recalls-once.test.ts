import { describe, expect, it } from "vitest";
import { join } from "node:path";
import { archFor } from "../../arch/registry.js";
import { budgetOf, FRESH, unmeteredQuota } from "../../core/budget.js";
import { localDispatch } from "../../core/dispatch.js";
import type { Harness } from "../../core/loop.js";
import { registryOf } from "../../core/registry.js";
import { buildSpec, type RunSpec } from "../../core/spec.js";
import { InProcessState } from "../../core/state.js";
import { recalledNotes, type RecallResult } from "../../contracts/memory.js";
import { InProcessDirectiveQueue } from "../../workflows/hunt/directives.js";
import type { HuntKinds } from "../../workflows/hunt/journal.js";
import { fold } from "../../workflows/hunt/ledger.js";
import { runHunt } from "../../workflows/hunt/workflow.js";
import { isLead, respondingProvider } from "../support/responding-provider.js";
import { countingMemory, recalledFixture } from "../support/recalled.js";

const FIXTURES = join(import.meta.dirname, "..", "fixtures");
const RUN = "run-recalls-once";
const ASKED = "192.0.2.10 is beaconing to attacker-controlled infrastructure";
const SUBJECT = "ip:192.0.2.10";
const RECALLED = recalledFixture();

function huntSpec(): RunSpec {
  const entry = archFor("hunt");
  const spec = buildSpec(
    { arch: entry.arch, playbook: join(FIXTURES, "hunt.playbook.yaml"), config: join(FIXTURES, "hunt.config.yaml") },
    entry.actions,
  );
  // Where a start job puts them: the hunt spec reads its own vocabulary off the
  // sections, and subjects arrive as keys the spec parses.
  return {
    ...spec,
    sections: {
      ...spec.sections,
      operator_hypotheses: [ASKED],
      operator_hypothesis_subjects: { [ASKED]: [SUBJECT] },
    },
  };
}

// Concludes on the first decision it is asked for, so the run reaches a terminal
// and the ledger holds every turn the lead took to get there.
const provider = respondingProvider({
  emit: (schema) =>
    isLead(schema) ? { action: "CONCLUDE", rationale: "nothing left to test", evidence_citations: [] } : { results: [] },
  ticks: 0,
});

async function hunt() {
  const state = new InProcessState<HuntKinds>();
  const spec = huntSpec();
  const memory = countingMemory(RECALLED);
  const harness: Harness<HuntKinds> = {
    provider,
    registry: registryOf([], {}),
    dispatch: localDispatch,
    budget: budgetOf(spec.budgets, unmeteredQuota, Date.now, FRESH),
    memory,
    state,
  };
  const report = await runHunt(harness, {
    run_id: RUN,
    spec,
    actions: archFor("hunt").actions,
    queue: new InProcessDirectiveQueue(),
  });
  return { report, memory, events: await state.read(RUN) };
}

describe("a hunt reads episodic memory once, on the keys the operator named", () => {
  it("reads on the subjects of the operator's own hypotheses", async () => {
    const { memory } = await hunt();
    expect(memory.reads()).toEqual([[SUBJECT]]);
  });

  it("journals that read as one event on the hunt's ledger", async () => {
    const { events } = await hunt();
    const recalls = events.filter((event) => event.kind === "recall");
    expect(recalls).toHaveLength(1);
    expect(recalls[0]?.payload).toEqual(RECALLED);
  });

  // Every iteration is a fresh turn for the lead, and every one of them reads the
  // journaled event rather than memory.
  it("reads memory once however many turns the hunt takes", async () => {
    const { memory } = await hunt();
    expect(memory.reads()).toHaveLength(1);
  });

  // No fold reads episodic: the projection is one run's own account of itself, and
  // a recalled row is an input to a decision rather than a belief the hunt holds.
  it("leaves the projection alone", async () => {
    const { events } = await hunt();
    const withRecall = fold(events);
    const without = fold(events.filter((event) => event.kind !== "recall"));
    expect(withRecall).toEqual(without);
  });

  it("renders what it recalled where the lead reads it", async () => {
    const { events } = await hunt();
    const recall = events.find((event) => event.kind === "recall");
    expect(recalledNotes(recall?.payload as RecallResult)[0]).toContain("scheduled backup target");
  });
});
