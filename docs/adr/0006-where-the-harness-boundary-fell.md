# 6. Where the harness boundary actually fell

Date: 2026-08-10

## Status

Accepted

## Context

ADR-0002 decided that a domain-free harness and a per-agent-type workflow are
two layers, and warned that the line between them "is drawn from a single real
case until the second workflow lands, so it should be expected to move once".
#592 built the harness, and building it forced several calls the earlier ADRs did
not make. This records them so a reviewer does not have to reverse-engineer them,
and so the ones most likely to move are named as such.

The harness is `services/agent/core/`, per `docs/migration-plan.md` §4 WS-A. `core` rather
than `harness` keeps one name for it in the tree and in the plan; the layer is
still called the harness everywhere it is discussed.

## Decision

### A provider makes one call; the loop belongs to the harness

`Provider.turn` is exactly one model call. The prototype's `llm_output` runs the
whole tool loop inside the provider module, and that placement is what would
have put the turn cap, the budget gate and the injection scan on the far side of
a seam a workflow can swap. With the loop in `services/agent/core/loop.ts`, `loop.ts` imports
no vendor SDK, the harness's own message shape is the only one it holds, and a
scripted provider is a drop-in — which is what lets the conformance workflow run
the real harness in CI with nothing faked but the model.

### The provider reports tokens; the budget prices them

`costOf` did not come across from `ai/llm.ts`. ADR-0005 names that function
collapsing tokens to dollars at the call site as the reason a run cannot be
re-priced, so pricing lives with the budget, as a method on it rather than a free
function the loop calls: a caller pricing its own spend could disagree with the
pool about what a call cost, and that is how a cap stops holding.

One assumption inside that arithmetic is not confirmed by measurement — whether
the gateway's normalised `prompt_tokens` includes a cache write. It is one
expression with a comment on it, so #593 correcting it is one edit.

### Approval is deployment configuration, not a property of a tool

Which tools ask a human first is a `ReadonlySet<string>` in the turn config, not
a field on `RegisteredTool`. #589's tool contract is settled, and `CONTEXT.md`
puts "which checkpoints ask a human" in the config layer. A gated call parks with
a `checkpoint` of class `tool_approval` and dispatches nothing; a `resolution` is
the only thing that unblocks it (ADR-0003), and a rejection comes back inside the
existing failure taxonomy as `refused` rather than as a park or a crash.

The checkpoint id is derived from the run, the tool and the arguments rather than
generated. That is what lets a resumed run recognise the resolution that answered
this exact call, and it is why an approval for one set of arguments does not
admit a different one.

### The turn cap stops the tool loop, not the run

A role that hit the cap still answers over what it gathered and reports `capped`.
Failing the turn instead would discard work already paid for. The run's own
ending stays the workflow's: a predicate the model does not control, backed by
the harness's iteration budget for a model that never chooses to stop.

### Two of #589's contracts had to grow

`Budget` gains `beginIteration(): Refusal | null`. Without it nothing advances
`Spend.iterations` and `max_iterations` is unenforceable. It is separate from
`reserve` because a tool loop is many model calls inside one iteration, so
counting calls would exhaust the limit far too early.

`RUN_KINDS` gains `tally`, the conformance workflow's kind. It is not a product
surface, and it is in the closed set rather than outside it so the workflow
exercises the same typed path a real one does.

### Memory ships as a port with a null implementation

Confirming the recommendation the migration plan and #592 both carried forward.
`nullMemory.recall` returning nothing is the seam's default rather than a stub:
a run's behaviour never silently depends on what a backend happened to remember,
and binding the contract to the component being replaced would have shaped it
wrongly.

### One provider surface

Only the OpenAI `/v1` wire is built. The gateway routes to either provider family
behind a model name, so a second wire carries nothing until #601 needs
`cache_control` and thinking. The token reader already understands both usage
shapes, because that difference is reported today.

### The domain-free requirement is checked

`services/agent/tests/core/domain-free.test.ts` greps every file under `services/agent/core/` for domain
vocabulary and refuses any import from `services/agent/workflows/`. ADR-0002's requirement
was previously only assertable. The harness may hold a workflow's events and call
its tools; it may not know which workflow, which is the distinction an import
would erase.

## Consequences

The conformance workflow (`services/agent/workflows/tally/`) is deliberately useless and is
expected to stay. It is what stops the boundary being re-drawn around whichever
workflow happens to be under active work, and it costs one small test file to
keep honest.

One hole is open and named. The loop returns its own events rather than appending
them, so a workflow commits them with its own and one iteration stays one
transaction. Nothing prevents a workflow from discarding them: the pool still
holds in memory so the cost cap survives, but the ledger's spend fold would
disagree with what was actually spent. #597 owns closing this when it adds the
per-run lease, because that is where re-entrancy is designed.

ADR-0002's warning still applies, and now has a specific target. The three
things most likely to move when `investigate` or `chat` lands are the shape of
the approval gate, whether `Memory.recall` takes a cue at all, and whether a
turn's transcript needs to be durable across a park rather than handed back to
the caller.

## Alternatives considered

**A provider that owns the tool loop**, as the prototype has it. Fewer moving
parts and one less port. Rejected: the approval gate and the injection scan would
sit inside a swappable component, so "no workflow can skip it" would be a
convention rather than a structure.

**Approval as a field on the tool contract.** Reads more naturally at the call
site. Rejected: it reopens a settled contract to encode a deployment decision,
and the same tool needs approval in one deployment and not in another.

**`commit` advancing the iteration count**, avoiding a contract change. Rejected:
one iteration is many model calls, so the limit would bind on call count and a
wide tool loop would exhaust it immediately.

**A branded, opaque journal the workflow cannot inspect**, closing the discarded
events hole by construction in the style of `defineTool`. Rejected for now: it is
machinery nobody asked for, and #597 has to touch this path anyway to add the
lease. Recorded here so the option is not rediscovered from scratch.
