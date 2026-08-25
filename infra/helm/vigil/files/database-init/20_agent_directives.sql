-- The operator's queue into a running agent. It sits beside agent_events rather
-- than on it: any process may enqueue here, while the ledger keeps one writer.

CREATE TABLE IF NOT EXISTS agent_directives (
    id           bigserial   PRIMARY KEY,
    run_id       uuid        NOT NULL,
    directive_id text        NOT NULL UNIQUE,
    kind         text        NOT NULL,
    actor        text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    payload      jsonb       NOT NULL
);

COMMENT ON TABLE agent_directives IS
    'Pending operator directives. Written by any process; drained onto agent_events by the run holding the ledger, which is what makes a directive take effect.';

COMMENT ON COLUMN agent_directives.directive_id IS
    'The directive''s identity on the ledger. Unique so a retried enqueue cannot queue the same directive twice, and so the drain can tell what it has already journaled.';

COMMENT ON COLUMN agent_directives.kind IS
    'Directive kind, validated in TypeScript against a closed union rather than constrained here, as agent_events.kind is.';

COMMENT ON COLUMN agent_directives.payload IS
    'The whole directive. The columns above are the envelope every workflow shares; everything a workflow owns its own vocabulary for stays in here, unread by the harness.';

-- A drain reads one run's queue in insertion order and nothing else does.
CREATE INDEX IF NOT EXISTS idx_agent_directives_run
    ON agent_directives (run_id, id);
