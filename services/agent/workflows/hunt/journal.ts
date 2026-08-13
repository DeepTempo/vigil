import { EVENT_SCHEMA_VERSION, type NewEvent, type RunKind } from "../../contracts/events.js";
import type { State } from "../../core/seams.js";
import { fold, type HuntEvent, type HuntKinds, type Projection } from "./ledger.js";

export type { HuntEvent, HuntKinds, Projection } from "./ledger.js";
import type { DirectiveQueue } from "./ports.js";
import type { HuntState } from "./types.js";

// run_id and run_kind come from the journal, not from each call site: a caller
// naming the wrong run would write into someone else's ledger.
export type Body = Omit<NewEvent<HuntKinds>, "run_id" | "run_kind">;

// The controller's ledger, backed by the State seam. append stays synchronous so
// the decision logic reads unchanged; flush is what makes an iteration durable.
// It carries the directive queue as well: the two stores are both scoped to this
// run, and holding them together is what lets a drain keep its signature.
export class Journal {
  private events: HuntEvent[] = [];
  private pending: Body[] = [];
  private view: Projection | null = null;
  private written = 0;

  private constructor(
    private readonly state: State<HuntKinds>,
    readonly queue: DirectiveQueue,
    readonly runId: string,
    private readonly runKind: RunKind,
  ) {}

  static async open(
    state: State<HuntKinds>,
    queue: DirectiveQueue,
    runId: string,
    runKind: RunKind = "hunt",
  ): Promise<Journal> {
    const journal = new Journal(state, queue, runId, runKind);
    journal.events = await state.read(runId);
    journal.written = journal.events.length;
    return journal;
  }

  static async create(
    state: State<HuntKinds>,
    queue: DirectiveQueue,
    runId: string,
    hunt: HuntState,
    runKind: RunKind = "hunt",
  ): Promise<Journal> {
    const journal = new Journal(state, queue, runId, runKind);
    journal.append({ kind: "run", payload: { hunt } } as unknown as Body);
    await journal.flush();
    return journal;
  }

  // Buffered, not written: an iteration lands as one transaction, so a crash
  // between two of its events cannot leave half an iteration on the ledger.
  //
  // ts is empty rather than stamped. Only the store stamps, so an unflushed event
  // has no time yet, and inventing one here meant this log and the persisted one
  // disagreed about when an event happened whenever the millisecond ticked
  // between the two. Nothing folds ts, so the value is unread until flush
  // replaces the whole log with what the store recorded.
  append(body: Body): HuntEvent {
    const event = {
      ...body,
      run_id: this.runId,
      run_kind: this.runKind,
      seq: this.events.length,
      ts: "",
      schema_version: EVENT_SCHEMA_VERSION,
    } as HuntEvent;
    this.pending.push(body);
    this.events.push(event);
    this.view = null;
    return event;
  }

  patch(target: string, id: string, fields: Record<string, unknown>): void {
    this.append({ kind: "patch", payload: { target, id, fields } } as unknown as Body);
  }

  // Read back rather than trusted: what the store recorded, with the seq and ts it
  // assigned, becomes this log. Nothing here can then drift from the ledger, which
  // is the same guarantee open() gets by loading it in the first place.
  async flush(): Promise<void> {
    if (this.pending.length === 0) return;
    const batch = this.pending;
    this.pending = [];
    const owned = batch.map((body) => ({ ...body, run_id: this.runId, run_kind: this.runKind }) as NewEvent<HuntKinds>);
    this.written = await this.state.append(this.runId, this.written, owned);
    this.events = await this.state.read(this.runId);
    this.view = null;
  }

  get projection(): Projection {
    if (this.view === null) this.view = fold(this.events);
    return this.view;
  }

  get log(): readonly HuntEvent[] {
    return this.events;
  }
}
