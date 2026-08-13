import type { Pool } from "pg";
import type { Claim, Leases } from "../core/leases.js";
import type { RunKind } from "../contracts/events.js";

// Every deadline is computed by now() rather than sent as a parameter. A worker
// whose clock runs fast would otherwise write a claim_until nobody can reach and
// hold a run forever, and the TTL is the whole basis for calling a worker dead.
export class LeaseRepository implements Leases {
  constructor(private readonly pool: Pool) {}

  // Insert on a first start, take over from anyone who is not driving the run, and
  // nothing at all while someone else is -- the ON CONFLICT filter is what refuses
  // the second worker, so no two processes drive one run.
  //
  // A null owner is nobody driving it, whatever claim_until says. Three things
  // write that state and all three mean the same: the sweeper reserving a run for
  // the queue, release() parking one, and a run that has never been claimed. The
  // deadline on such a row is when to *look* again, not a licence to wait -- so a
  // worker holding that run's job takes it now rather than sitting out an interval
  // nobody is using. Without this arm the sweeper's own reservation locks out the
  // very worker it queued the job for, and no run is ever resumed.
  async claim(runId: string, runKind: RunKind, owner: string, ttlMs: number): Promise<boolean> {
    const result = await this.pool.query(
      `INSERT INTO agent_run_leases (run_id, run_kind, owner, claim_until)
       VALUES ($1, $2, $3, now() + make_interval(secs => $4::double precision))
       ON CONFLICT (run_id) DO UPDATE
         SET owner = $3, run_kind = $2, claim_until = now() + make_interval(secs => $4::double precision)
         WHERE agent_run_leases.claim_until < now() OR agent_run_leases.owner IS NULL
       RETURNING run_id`,
      [runId, runKind, owner, ttlMs / 1000],
    );
    return result.rowCount === 1;
  }

  // Owner rather than expiry: if the claim lapsed and nobody took it, the holder
  // still holds it, and killing a run over a moment of starvation would be worse
  // than the late renewal it is recovering from.
  async renew(runId: string, owner: string, ttlMs: number): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE agent_run_leases SET claim_until = now() + make_interval(secs => $3::double precision)
       WHERE run_id = $1 AND owner = $2
       RETURNING run_id`,
      [runId, owner, ttlMs / 1000],
    );
    return result.rowCount === 1;
  }

  // The row stays: a parked run is unfinished, and its presence is what keeps the
  // sweeper looking at it until it is answered or its park TTL runs out.
  async release(runId: string, owner: string, afterMs: number): Promise<void> {
    await this.pool.query(
      `UPDATE agent_run_leases SET owner = NULL, claim_until = now() + make_interval(secs => $3::double precision)
       WHERE run_id = $1 AND owner = $2`,
      [runId, owner, afterMs / 1000],
    );
  }

  // The one write the API makes rather than the worker; it lives here too so both
  // sides agree on what nudging a parked run means, the same reason terminal() sits
  // on the ledger repository. Python's copy is core/agents/directives.py::_wake.
  //
  // Only a run still waiting. Pulling a held claim forward would declare a live
  // worker dead, which is the one thing a nudge must never do.
  async wake(runId: string): Promise<void> {
    await this.pool.query(
      "UPDATE agent_run_leases SET claim_until = now() WHERE run_id = $1 AND owner IS NULL",
      [runId],
    );
  }

  async finish(runId: string): Promise<void> {
    await this.pool.query("DELETE FROM agent_run_leases WHERE run_id = $1", [runId]);
  }

  // Discovery and the reservation are one statement, so only the sweeper that won a
  // row enqueues it. SKIP LOCKED means a second sweeper moves on to other runs
  // rather than waiting behind the first, which is what makes N replicas harmless.
  //
  // owner stays NULL: the sweeper queues the run, it does not drive it, and a row
  // it stamped with its own name would lock out the worker that picks the job up.
  // The deadline it writes is how long to wait for that worker before offering the
  // run again, so it budgets queue latency rather than work.
  async sweep(ttlMs: number, limit: number): Promise<Claim[]> {
    const result = await this.pool.query<Claim>(
      `UPDATE agent_run_leases SET owner = NULL, claim_until = now() + make_interval(secs => $1::double precision)
       WHERE run_id IN (
         SELECT run_id FROM agent_run_leases
         WHERE claim_until < now()
         ORDER BY claim_until
         LIMIT $2
         FOR UPDATE SKIP LOCKED
       )
       RETURNING run_id, run_kind`,
      [ttlMs / 1000, limit],
    );
    return result.rows;
  }
}
