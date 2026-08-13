import { describe, expect, it } from "vitest";
import type { Pool } from "pg";
import { LedgerRepository } from "../../ledger/repository.js";
import { InProcessState } from "../../core/state.js";
import { nullMemory } from "../../core/memory.js";
import { localDispatch } from "../../core/dispatch.js";
import { defineTool } from "../../contracts/tool.js";
import type { State } from "../../core/seams.js";

const RUN = "9c1c2d3e-0000-4000-8000-000000000592";

// The point of the State seam: the Postgres repository satisfies it as written,
// with no adapter. Loosening either side fails typecheck rather than review.
const repository: State = new LedgerRepository({} as Pool);
void repository;

describe("the State seam", () => {
  it("assigns seq itself and reads back in order", async () => {
    const state = new InProcessState();
    const next = await state.append(RUN, [
      { run_id: RUN, run_kind: "tally", kind: "terminal", payload: { outcome: "completed", reason: "done" } },
    ]);

    expect(next).toBe(1);
    expect(await state.latestSeq(RUN)).toBe(0);
    expect((await state.read(RUN))[0]?.seq).toBe(0);
    expect(await state.terminal(RUN)).toEqual({ outcome: "completed", reason: "done" });
  });

  // No caller offers a position, so two writers cannot claim one. What used to be
  // a conflict is now the second writer simply landing after the first.
  it("gives a second writer the position after the first", async () => {
    const state = new InProcessState();
    const event = {
      run_id: RUN,
      run_kind: "tally" as const,
      kind: "terminal" as const,
      payload: { outcome: "completed" as const, reason: "done" },
    };
    await state.append(RUN, [event]);
    expect(await state.append(RUN, [event])).toBe(2);
    expect((await state.read(RUN)).map((one) => one.seq)).toEqual([0, 1]);
  });

  // Interleaved rather than sequential: the seam is what a parallel round writes
  // through, and it must not depend on the caller awaiting one append at a time.
  it("numbers concurrent appends without collision", async () => {
    const state = new InProcessState();
    const event = { run_id: RUN, run_kind: "tally" as const, kind: "patch" as const, payload: { target: "t", id: "i", fields: {} } };
    await Promise.all(Array.from({ length: 8 }, () => state.append(RUN, [event])));
    expect((await state.read(RUN)).map((one) => one.seq)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
  });

  // A caller holding a read result must not be able to reach into the log; the
  // Postgres implementation hands out fresh rows, so this one hands out clones.
  it("does not hand out the log itself", async () => {
    const state = new InProcessState();
    await state.append(RUN, [
      { run_id: RUN, run_kind: "tally", kind: "terminal", payload: { outcome: "completed", reason: "done" } },
    ]);

    const first = await state.read(RUN);
    first[0]!.kind = "patch";
    expect((await state.read(RUN))[0]?.kind).toBe("terminal");
  });

  it("reports no ledger rather than an empty one for a run that has none", async () => {
    expect(await new InProcessState().latestSeq(RUN)).toBeNull();
  });
});

describe("the Memory seam", () => {
  it("recalls nothing, so no run depends on what a backend happened to keep", async () => {
    await nullMemory.remember("something worth keeping");
    expect(await nullMemory.recall("something", 10)).toEqual([]);
  });
});

describe("the ToolDispatch seam", () => {
  it("carries the call to the tool and its bounds along with it", async () => {
    let seenMaxRows = 0;
    const tool = defineTool(
      {
        id: "echo",
        description: "returns what it was given",
        parameters: {},
        execute: async (args, bounds) => {
          seenMaxRows = bounds.maxRows;
          return { ok: true, rows: [args], rowCount: 1, capped: false, sourceSystem: "test" };
        },
      },
      { maxRows: 7, timeoutMs: 1_000 },
    );

    const result = await localDispatch.invoke(tool, { n: 1 });
    expect(result.ok && result.rows).toEqual([{ n: 1 }]);
    expect(seenMaxRows).toBe(7);
  });
});
