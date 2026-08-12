import { describe, expect, it } from "vitest";
import type { NewEvent, ResolutionPayload } from "../../contracts/events.js";
import { httpAnswers, journalAnswers, noAnswers, resolutionsOf, type Answers } from "../../core/answers.js";
import { TOOL_APPROVAL } from "../../core/loop.js";
import { InProcessState } from "../../core/state.js";

const RUN = "7d3c2d3e-0000-4000-8000-000000000e29";
const CHECKPOINT = "apr-c0ffee";

const parked = (checkpoint_id = CHECKPOINT): NewEvent<Record<never, never>> => ({
  run_id: RUN,
  run_kind: "investigate",
  kind: "checkpoint",
  payload: { checkpoint_id, checkpoint_class: TOOL_APPROVAL, question: "isolate?", raised_at: "2026-08-12T00:00:00Z" },
});

const resolution = (checkpoint_id = CHECKPOINT, answer: "approve" | "reject" = "approve"): ResolutionPayload => ({
  checkpoint_id,
  actor: "analyst",
  answer,
  text: "",
  resolved_at: "2026-08-12T00:01:00Z",
});

const answering = (...payloads: readonly ResolutionPayload[]): Answers =>
  async () =>
    [...payloads];

async function ledgerWith(...events: readonly NewEvent<Record<never, never>>[]): Promise<InProcessState> {
  const state = new InProcessState();
  if (events.length > 0) await state.append(RUN, 0, events);
  return state;
}

const journaled = async (state: InProcessState) =>
  (await state.read(RUN)).filter((event) => event.kind === "resolution").map((event) => event.payload as ResolutionPayload);

describe("an answer becomes a ledger event, once", () => {
  it("journals an answer to a checkpoint this run raised", async () => {
    const state = await ledgerWith(parked());
    expect(await journalAnswers(state, RUN, "investigate", answering(resolution()))).toBe(1);
    expect((await journaled(state))[0]?.checkpoint_id).toBe(CHECKPOINT);
  });

  it("journals a rejection as readily as an approval", async () => {
    const state = await ledgerWith(parked());
    await journalAnswers(state, RUN, "investigate", answering(resolution(CHECKPOINT, "reject")));
    expect((await journaled(state))[0]?.answer).toBe("reject");
  });

  it("appends nothing the second time, so a resume that answers nothing writes nothing", async () => {
    const state = await ledgerWith(parked());
    const answers = answering(resolution());

    expect(await journalAnswers(state, RUN, "investigate", answers)).toBe(1);
    expect(await journalAnswers(state, RUN, "investigate", answers)).toBe(0);
    expect(await journaled(state)).toHaveLength(1);
  });

  it("ignores an answer to a checkpoint nobody raised", async () => {
    // It would resolve nothing and sit on the ledger looking like it had.
    const state = await ledgerWith(parked("apr-ours"));
    expect(await journalAnswers(state, RUN, "investigate", answering(resolution("apr-someone-elses")))).toBe(0);
  });

  it("journals only the fresh one when a second checkpoint is answered later", async () => {
    const state = await ledgerWith(parked("apr-one"), parked("apr-two"));
    await journalAnswers(state, RUN, "investigate", answering(resolution("apr-one")));
    await journalAnswers(state, RUN, "investigate", answering(resolution("apr-one"), resolution("apr-two")));

    expect((await journaled(state)).map((one) => one.checkpoint_id)).toEqual(["apr-one", "apr-two"]);
  });

  it("answers nothing when there is nobody to ask", async () => {
    const state = await ledgerWith(parked());
    expect(await journalAnswers(state, RUN, "investigate", noAnswers)).toBe(0);
  });
});

describe("what counts as an answer on the wire", () => {
  it("takes approve and reject", () => {
    const body = { decisions: [resolution("a"), resolution("b", "reject")] };
    expect(resolutionsOf(body).map((one) => one.answer)).toEqual(["approve", "reject"]);
  });

  it("drops anything that is not one of the two", () => {
    // "pending" is a row that exists and has not been answered. Journaling it
    // would unblock a call nobody approved.
    const body = { decisions: [{ checkpoint_id: "a", answer: "pending" }, { checkpoint_id: "b" }] };
    expect(resolutionsOf(body)).toEqual([]);
  });

  it("reads an absent or malformed body as no answers", () => {
    expect(resolutionsOf(null)).toEqual([]);
    expect(resolutionsOf({ decisions: "soon" })).toEqual([]);
  });
});

describe("reading answers over HTTP", () => {
  it("presents the shared secret and asks about the one run", async () => {
    let seen = { url: "", auth: "" };
    const answers = httpAnswers({
      url: "http://localhost:6987/internal/runs/",
      token: "shhh",
      fetch: async (input, init) => {
        seen = { url: String(input), auth: String((init?.headers as Record<string, string>)["authorization"]) };
        return new Response(JSON.stringify({ decisions: [resolution()] }), { status: 200 });
      },
    });

    expect(await answers(RUN)).toHaveLength(1);
    expect(seen.url).toBe(`http://localhost:6987/internal/runs/${RUN}/decisions`);
    expect(seen.auth).toBe("Bearer shhh");
  });

  it("throws rather than reporting no answers when the endpoint refuses", async () => {
    // Silence here reads exactly like "nothing approved yet", and the run would
    // park forever against an answer that exists.
    const answers = httpAnswers({ url: "http://localhost:6987/internal/runs", token: "shhh", fetch: async () => new Response("", { status: 503 }) });
    await expect(answers(RUN)).rejects.toThrow(/answered 503/);
  });
});
