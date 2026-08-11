import { EVENT_SCHEMA_VERSION, type AgentEvent, type NewEvent, type TerminalPayload } from "../contracts/events.js";
import { SeqConflict } from "../ledger/repository.js";
import type { State } from "./seams.js";

// The State seam without Postgres. It reproduces rather than approximates the
// composite key's guarantees, so a caller cannot tell the two implementations apart.
export class InProcessState<Kinds extends Record<string, unknown> = Record<never, never>> implements State<Kinds> {
  private readonly runs = new Map<string, AgentEvent<Kinds>[]>();

  private log(runId: string): AgentEvent<Kinds>[] {
    const existing = this.runs.get(runId);
    if (existing !== undefined) return existing;
    const created: AgentEvent<Kinds>[] = [];
    this.runs.set(runId, created);
    return created;
  }

  async latestSeq(runId: string): Promise<number | null> {
    const log = this.log(runId);
    return log.length === 0 ? null : Math.max(...log.map((event) => event.seq));
  }

  async read(runId: string): Promise<AgentEvent<Kinds>[]> {
    return structuredClone(this.log(runId)).sort((left, right) => left.seq - right.seq);
  }

  async append(runId: string, from: number, events: readonly NewEvent<Kinds>[]): Promise<number> {
    if (events.length === 0) return from;
    const log = this.log(runId);
    const end = from + events.length;
    if (log.some((event) => event.seq >= from && event.seq < end)) throw new SeqConflict(runId, from);

    const ts = new Date().toISOString();
    let seq = from;
    for (const event of events) {
      log.push({ ...event, seq: seq++, ts, schema_version: EVENT_SCHEMA_VERSION } as AgentEvent<Kinds>);
    }
    return seq;
  }

  async terminal(runId: string): Promise<TerminalPayload | null> {
    const events = await this.read(runId);
    const found = events.find((event) => event.kind === "terminal");
    return found === undefined ? null : (found.payload as TerminalPayload);
  }
}
