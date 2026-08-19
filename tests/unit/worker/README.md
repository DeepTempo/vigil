# Worker job tests

`test_worker_jobs.py` was deleted in #632. Its five cases covered
`_adapt_router_result_to_raw`, which existed to shape a router result into the
Anthropic `tool_use` blocks **AgentRunner's loop** read — and that loop was
deleted in #629, taking `llm_call_raw` and the whole raw-call chain with it.

The guarantee it protected — a tool call must survive the round trip — now lives
where the tool loop does: `services/agent/tests/core/stream.test.ts`.
