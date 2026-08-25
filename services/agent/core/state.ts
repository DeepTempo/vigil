import { EVENT_SCHEMA_VERSION, type AgentEvent, type NewEvent, type TerminalPayload } from "../contracts/events.js";
import type { ReadOptions, State } from "./seams.js";

// The State seam without Postgres. It reproduces rather than approximates the
// composite key's guarantees, so a caller cannot tell the two implementations apart.
export class InProcessState<Kinds extends Record<string, unknown> = Record<never, never>> implements State<Kinds> {
  private readonly runs = new Map<string, AgentEvent<Kinds>[]>();

  // The store's clock, injectable like the lease's: no caller may supply a ts, so
  // reaching a run parked past its TTL means moving this.
  constructor(private readonly now: () => number = Date.now) {}

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

  async read(runId: string, opts: ReadOptions = {}): Promise<AgentEvent<Kinds>[]> {
    const since = opts.since ?? 0;
    const rows = structuredClone(this.log(runId).filter((event) => event.seq >= since));
    rows.sort((left, right) => left.seq - right.seq);
    if (opts.snapshots === true) return rows;
    return rows.map(({ snapshot: _dropped, ...rest }) => rest as AgentEvent<Kinds>);
  }

  // The position comes from the log, never from the caller. Nothing is awaited
  // inside the loop, so a batch lands as atomically as the Postgres transaction.
  async append(runId: string, events: readonly NewEvent<Kinds>[]): Promise<number> {
    const log = this.log(runId);
    let seq = log.reduce((highest, event) => Math.max(highest, event.seq), -1);
    if (events.length === 0) return seq + 1;

    const ts = new Date(this.now()).toISOString();
    for (const event of events) {
      log.push({ ...event, seq: ++seq, ts, schema_version: EVENT_SCHEMA_VERSION } as AgentEvent<Kinds>);
    }
    return seq + 1;
  }

  async terminal(runId: string): Promise<TerminalPayload | null> {
    const events = await this.read(runId);
    const found = events.find((event) => event.kind === "terminal");
    return found === undefined ? null : (found.payload as TerminalPayload);
  }
}
