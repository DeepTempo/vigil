import type { RunKind } from "../contracts/events.js";

// Not one of the four seams: the harness never receives this and a turn has no
// business renewing a lease. It is the composition root's, held by whatever
// drives a run and by the sweeper that reclaims one nobody is driving.

// Deployment timings, so a slow cluster can widen them without a rebuild. They are
// not in core/config.py: that is Python's settings surface and nothing in this
// layer reads it.
function ms(name: string, fallback: number): number {
  const raw = Number(process.env[name]);
  return Number.isFinite(raw) && raw > 0 ? raw : fallback;
}

// How long a claim lasts, and how often its holder pushes it forward. The margin
// is 4x rather than 3x because renewal shares an event loop with a fold that can
// block it: a live worker declared dead pays for an LLM call it cannot record,
// while a lease held too long only delays a reclaim. Money loses to seconds.
export const LEASE_TTL_MS = ms("VIGIL_LEASE_TTL_MS", 60_000);
export const RENEW_EVERY_MS = ms("VIGIL_LEASE_RENEW_MS", 15_000);

// How often the sweeper looks, and how long a parked run waits before it is
// looked at again. The park interval is the safety net once the console pushes
// claim_until forward on an answer; until then it is the only path.
export const SWEEP_EVERY_MS = ms("VIGIL_SWEEP_MS", 30_000);
export const PARK_EVERY_MS = ms("VIGIL_PARK_POLL_MS", 60_000);

// A run the sweeper reserved and must now hand to the queue. run_kind is here
// because a resume job needs it and the ledger read would be a second query.
export interface Claim {
  run_id: string;
  run_kind: RunKind;
}

export interface Leases {
  // False when someone else is *driving* the run. A null owner is nobody driving
  // it -- a run the sweeper reserved, or one parked waiting for an answer -- and
  // the worker holding its job may take it. Refusal is not a failure: the caller
  // returns rather than throwing, because a run already being driven is the good
  // case.
  claim(runId: string, runKind: RunKind, owner: string, ttlMs: number): Promise<boolean>;
  // False when the claim was stolen, which tells the holder it has been declared
  // dead and should stop paying for work nobody will record.
  renew(runId: string, owner: string, ttlMs: number): Promise<boolean>;
  // The run parked. The row stays -- it is unfinished -- and nothing touches it
  // until the interval passes or the console pulls it forward.
  release(runId: string, owner: string, afterMs: number): Promise<void>;
  // Something arrived for a parked run, so the next sweep should pick it up rather
  // than waiting out its interval. No owner to match: whoever held the run has
  // already let go, and the caller is an API process that never held it.
  wake(runId: string): Promise<void>;
  // The run journaled its terminal, so it is nobody's work now.
  finish(runId: string): Promise<void>;
  // Discovery and reservation in one step, so N sweepers cannot enqueue one run
  // twice. The sweeper takes no ownership -- it is not going to drive the run,
  // only queue it -- so the row keeps a null owner and the worker that dequeues
  // the job is the one that claims it. ttlMs is how long the reservation holds
  // the run off the next sweep, which is the queue latency being budgeted for.
  sweep(ttlMs: number, limit: number): Promise<Claim[]>;
}

interface Held {
  run_kind: RunKind;
  owner: string | null;
  claim_until: number;
}

// The Leases port without Postgres, so a resume test needs no database. It is
// this process's clock rather than the store's, which is the same substitution
// InProcessState makes: neither implementation lets a caller supply a time.
export class InProcessLeases implements Leases {
  private readonly runs = new Map<string, Held>();

  constructor(private readonly now: () => number = Date.now) {}

  async claim(runId: string, runKind: RunKind, owner: string, ttlMs: number): Promise<boolean> {
    const held = this.runs.get(runId);
    const driven = held !== undefined && held.owner !== null && held.claim_until > this.now();
    if (driven) return false;
    this.runs.set(runId, { run_kind: runKind, owner, claim_until: this.now() + ttlMs });
    return true;
  }

  async renew(runId: string, owner: string, ttlMs: number): Promise<boolean> {
    const held = this.runs.get(runId);
    if (held === undefined || held.owner !== owner) return false;
    held.claim_until = this.now() + ttlMs;
    return true;
  }

  async release(runId: string, owner: string, afterMs: number): Promise<void> {
    const held = this.runs.get(runId);
    if (held === undefined || held.owner !== owner) return;
    this.runs.set(runId, { ...held, owner: null, claim_until: this.now() + afterMs });
  }

  // Only a run still waiting: a held one is being worked on already, and moving its
  // deadline back would declare a live worker dead.
  async wake(runId: string): Promise<void> {
    const held = this.runs.get(runId);
    if (held === undefined || held.owner !== null) return;
    held.claim_until = this.now();
  }

  async finish(runId: string): Promise<void> {
    this.runs.delete(runId);
  }

  // Due at or before now, not strictly before: Postgres gets the same answer from
  // a strict < because now() is the transaction's, and a later transaction's is
  // later. There is no transaction here, so a wake() that set the deadline to this
  // instant would be invisible to a sweep in the same millisecond.
  async sweep(ttlMs: number, limit: number): Promise<Claim[]> {
    const due = [...this.runs.entries()]
      .filter(([, held]) => held.claim_until <= this.now())
      .sort((left, right) => left[1].claim_until - right[1].claim_until)
      .slice(0, limit);

    for (const [runId, held] of due) {
      this.runs.set(runId, { ...held, owner: null, claim_until: this.now() + ttlMs });
    }
    return due.map(([run_id, held]) => ({ run_id, run_kind: held.run_kind }));
  }
}
