# Compose is a sequencer, not a lead loop

Every run kind on the harness so far drives `runLead`: a lead emits one decision
per iteration, names a worker, and the loop dispatches it. Compose does not, and
will not. A Playbook already states its Phases in order — triage, then
investigate, then contain, then report — so there is no decision for a lead to
make. Compose is a deterministic sequencer that calls the harness once per Phase
with that Phase's agent as the role, which is `lead/workflow.ts`'s `dispatch()`
with the decider removed.

## Why not a lead

Putting a Playbook through `runLead` means an LLM turn per Phase spent choosing
what an analyst already wrote down, and a model free to choose otherwise. For a
forensic or compliance Playbook the ordering *is* the product: evidence is
acquired before it is analysed, and a report is written last because it rests on
everything above it. A lead that can reorder or skip a Phase is not a more
flexible version of that — it is a weaker guarantee. The Python phase loop being
replaced walks `for idx in range(start_index, len(phases))` and cannot reorder;
an approval may abort a run but never reroute it. Determinism is the faithful
port, not a simplification of one.

The alternative considered and rejected was a vestigial lead whose vocabulary is
`NEXT_PHASE` / `CONCLUDE`. It needs no loader change and ships entirely inside
one ticket, which is the whole of its case. It also spends a model call to read
a list, and leaves the ordering guarantee resting on a prompt.

## What it costs

`parseRoles` hard-requires a lead, and `assertVocabulary` requires that lead's
`output_schema` to carry a non-empty `action` enum. A workers-only arch means
`roles.lead` becomes optional, and the lead-specific assembly — `roster()` and
`constrainWorkerId()` — is skipped rather than fed an empty roster.

## Consequences

- **The Playbook is the registry for a Workflow.** Phase order, per-phase
  instructions, and the catalog facts the Workflows screen shows all live in one
  file and everything else derives from it. `agents:` is deleted: `phases[].agent`
  already states it, and the two agreeing today is luck, not a guarantee. This is
  ADR-0001's rule applied to a second domain.
- **Phase order needs a home the three-file split lacks.** It goes in the
  playbook layer as an ordered `phases` list, not in `directives` — a `Record`
  keyed by role cannot express *triage → investigate → triage again*, which the
  `phases` JSONB column already permits and `workflow_run_phases` already keys by
  `phase_id` rather than agent.
- **Agent prompts are never restated in YAML.** The roster is runtime data —
  `SOCAgentLibrary` loads DB-backed custom agents, and a user can edit a builtin.
  An arch file listing thirteen roles would be stale on the first edit, with the
  user's own change on the losing side. The worker resolves the Playbook by
  reference at run start and journals what it resolved, so a replay reproduces
  the prompts the run actually used.
- **Compose is the first workflow wired into the worker.** `advance()` currently
  journals a spec and terminates with "nothing consumes it yet". The
  `run_kind` → workflow dispatch that replaces it is written generically, because
  the investigate and chat workflows need the same seam.
