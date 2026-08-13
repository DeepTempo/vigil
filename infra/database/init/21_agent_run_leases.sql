-- A row per in-flight run: who is working on it, and when that claim lapses. It
-- holds no copy of a ledger fact, so it can only be late, never wrong.

CREATE TABLE IF NOT EXISTS agent_run_leases (
    run_id      uuid        PRIMARY KEY,
    run_kind    text        NOT NULL,
    owner       text,
    claim_until timestamptz NOT NULL
);

COMMENT ON TABLE agent_run_leases IS
    'One row per in-flight run. The row exists until the run journals its terminal; claim_until says nobody may touch it before then.';

COMMENT ON COLUMN agent_run_leases.claim_until IS
    'Written and compared with the database clock only, so a worker whose clock runs fast cannot hold an unkillable lease.';

COMMENT ON COLUMN agent_run_leases.owner IS
    'Which worker is driving the run, or NULL when nobody is -- reserved for the queue, parked on an answer, or never started. Whether it is null decides who may claim; which worker it names is only for the console to report.';

-- The sweeper's only query, and it claims in the same statement it discovers by.
CREATE INDEX IF NOT EXISTS idx_agent_run_leases_due
    ON agent_run_leases (claim_until);
