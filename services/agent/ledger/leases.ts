import type { Pool } from "pg";
import type { Claim, Leases } from "../core/leases.js";
import type { RunKind } from "../contracts/events.js";

// Every deadline is now()'s, never a parameter: a worker with a fast clock would
// otherwise write a claim_until nobody can reach and hold the run forever.
export class LeaseRepository implements Leases {
  constructor(private readonly pool: Pool) {}

  // The ON CONFLICT filter refuses the second worker, so no two drive one run. A
  // null owner is nobody driving, whatever claim_until says, and may be taken now.
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

  // Owner rather than expiry: a lapsed claim nobody took is still the holder's, and
  // killing a run over a moment of starvation is the worse trade.
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

  // The API's write, not the worker's; here so both sides agree what a nudge means.
  // Only a waiting run: pulling a held claim forward would declare a live worker dead.
  async wake(runId: string): Promise<void> {
    await this.pool.query(
      "UPDATE agent_run_leases SET claim_until = now() WHERE run_id = $1 AND owner IS NULL",
      [runId],
    );
  }

  async finish(runId: string): Promise<void> {
    await this.pool.query("DELETE FROM agent_run_leases WHERE run_id = $1", [runId]);
  }

  // Discovery and reservation in one statement, and SKIP LOCKED so N replicas are
  // harmless. owner stays NULL, or the row locks out the worker it queued for.
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
