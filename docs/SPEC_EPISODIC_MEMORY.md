# Episodic memory: what runs saw and concluded, joined on entity keys

## Problem Statement

Every threat hunt starts from nothing. A run that concluded last month that `web-01` plus a particular alert is the nightly Veeam backup leaves no trace a later run can read, so the next hunt over the same host re-derives the same conclusion from the same telemetry, at the same cost. The harness has a `Memory` port for exactly this and the only implementation shipped is `nullMemory` — the seam is named, injected, and empty.

The store that does exist, MemPalace, is the wrong shape for the question. It is a search engine over prose: an agent writes *"10.2.3.4 appears to be backup traffic, closing as false positive"* as a sentence, and a later agent asking whether that address has been seen gets the five most similar-sounding paragraphs. "Have we seen this exact address" wants a yes or a no, not five best guesses. It also ships empty in every deployment — nothing seeds it, so it only ever holds what that install's own agents wrote — and both of its write paths swallow their failure at `logger.debug`, so a dead store reads as healthy to the daemon and to chat.

There is a live correctness defect on the same path. `get_shared_iocs()` answers cross-investigation overlap by intersecting two in-memory sets, so correlation history resets whenever the daemon restarts. The `shared_iocs` table it should be reading was declared, registered for `create_all`, given a schema and created by a migration — with no reader and no writer of the data anywhere.

## Solution

An episodic memory tier in the Postgres instance Vigil already runs, holding what runs saw and what they concluded, joined on exact entity keys rather than retrieved by similarity.

A run reads it once at start: the entity keys in its spec are looked up, the result is rendered into the frozen prompt prefix, and the rows that came back are journaled so the run stays replayable after the database has moved on. Workers reach the same data mid-run through a backend tool. When a run reaches its terminal, a Python job polls for it and derives rows from its **Ledger** — outside the run, so it can be re-run and so memory can be rebuilt from ledgers if it is ever lost.

Memory may change what a run looks at first. It may never change what counts as having found something. That is ADR 0015 and it is the constraint every part of this design answers to: no status on an entity, ranking returns a permutation of the **Frontier** rather than a filter, **Recall** never contributes to corroboration, ranking reads counted facts and never prose, and unanswered questions rank up.

What this buys is coverage, not a smaller bill. A run does not skip work it would otherwise do; it stops spending its budget re-establishing what an earlier run already concluded.

## User Stories

1. As a Hunt Lead, I want the entity keys in my run spec looked up before my first decision, so that I begin from what earlier runs concluded rather than re-deriving it.
2. As a Hunt Lead, I want prior conclusions to reorder my **Frontier**, so that I reach the interesting hypothesis in fewer iterations.
3. As a Hunt Lead, I want a host with a clean history still to appear in my Frontier, so that an adversary cannot earn low priority by looking boring.
4. As a Hunt Lead, I want a host with a malicious history to still require its own evidence, so that one weak signal plus an old incident cannot reach a verdict.
5. As a Hunt Lead, I want to see a prior **Verdict**'s rationale rendered for me, so that I can judge it myself.
6. As a Hunt Lead, I want that rationale to reach no ranking function, so that confident-sounding model prose cannot move priorities.
7. As a Hunt Lead, I want to be told how many recalled rows were dropped for budget, so that I know my view of history is partial.
8. As a Hunt Lead, I want an entity with no history to leave my Frontier unchanged, so that novelty is the hunt's own concern rather than something memory asserts.
9. As a worker, I want to look up an entity I discovered at iteration 7, so that a mid-run pivot reaches history the run spec never named.
10. As a worker, I want that lookup to be an ordinary tool call, so that it is journaled and costed like querying Splunk.
11. As a worker, I want exact-key lookups without needing the lead, so that I am not blocked on a decision turn to answer a factual question.
12. As a security architect, I want prose search restricted to the lead, so that attacker-authored text enters a run in one auditable place rather than a hundred.
13. As an operator, I want a run's recalled rows written into its **Ledger**, so that replaying that run months later shows what it actually saw.
14. As an operator, I want the ranking parameters copied into that record, so that a replay does not rerank under today's curve against rows chosen under the old one.
15. As an operator, I want recall rendered once into the frozen prefix, so that byte-identical prompt caching keeps working (ADR 0009).
16. As an operator, I want every read of memory logged whoever asked, so that "we can see what it knew" is true for callers that have no Ledger.
17. As a triage agent, I want to know an address was ruled a false positive three times, so that I spend my attention on what has not been settled.
18. As a Python agent, I want the same lookup tools the harness uses, so that retiring MemPalace is not a loss of capability.
19. As a chat user, I want to ask what we know about a host, so that I get the same history a hunt would.
20. As a security architect, I want chat never to write episodic memory, so that an analyst thinking aloud cannot become recalled history.
21. As an analyst, I want closing a case as a false positive to reach memory, so that my determination outranks three models agreeing.
22. As an analyst, I want my manually-created case to reach memory even with no Findings behind it, so that human-entered work is not silently dropped.
23. As an analyst, I want a case-derived **Verdict** to say its activity window was asserted rather than observed, so that nothing claims precision it does not have.
24. As a daemon operator, I want cross-investigation overlap answered from the database, so that correlation history survives a restart.
25. As a daemon operator, I want a failed memory write to be loud, so that a dead store does not read as healthy.
26. As a Hunt Lead, I want a question an earlier run never got to surfaced as a **Declared Gap**, so that work abandoned for budget is not abandoned forever.
27. As a Hunt Lead, I want a Gap's boost to come from accumulation on an entity, so that the ordinary case of a run ending with open questions does not flood the Frontier.
28. As a Hunt Lead, I want a hypothesis handed to incident response recorded as such, so that escalation leaves a trace and is not mistaken for a failure to look.
29. As an operator, I want a run that aborted to write nothing, so that no half-concluded verdict is asserted as memory.
30. As an operator, I want a run that concluded nothing to still be marked processed, so that legitimately inconclusive runs are not reprocessed forever.
31. As an operator, I want the save job safe to re-run, so that a retry after a partial failure converges rather than compounding.
32. As an operator, I want a distil version I can bump, so that changing the derivation re-derives history instead of leaving two generations of rows mixed.
33. As a data engineer, I want **Sightings** stored one row per entity, investigation and source, so that the tier grows with hunts rather than with telemetry volume.
34. As a data engineer, I want a per-key cap on recall, so that one entity in every hunt cannot consume the whole token budget.
35. As a data engineer, I want a total order on every recall query, so that the recalled set is deterministic and a replay diff means a real change.
36. As a ranking author, I want a **Verdict**'s counted facts — outcome, sources, **Stance**, dates, **Trust** — so that I can order without reading prose.
37. As a ranking author, I want **Source Tier** on each source, so that two telemetry sources agreeing outweighs two feeds agreeing.
38. As a ranking author, I want `not_evidence` sources to be impossible on a Verdict, so that a rule catalogue is never cited as an observation.
39. As a ranking author, I want a Verdict's activity window separate from its conclusion date, so that a retrospective sweep over old archives is not treated as newly relevant.
40. As a ranking author, I want to know whether a window was observed or asserted, so that I can discount the weaker one.
41. As a ranking author, I want a Verdict to name only its subject entities, so that infrastructure a run walked past does not inherit the weight of a confirmed intrusion (ADR 0016).
42. As an evaluator, I want eval runs to read a frozen copy of memory, so that scores stay comparable across commits as the live tier fills.
43. As an evaluator, I want an empty frozen copy, so that I can measure what memory is worth by difference.
44. As an evaluator, I want a recorded run whose prefix carries recalled rows in the fold-equivalence suite, so that the gate does not pass vacuously on this feature.
45. As a maintainer, I want memory reads to work without narrative search, so that the exact-join tier ships and is useful before any retrieval infrastructure is chosen.
46. As a maintainer, I want the **Distil** to read the harness's typed conclusions rather than re-derive them, so that there is one fold rather than two drifting apart.
47. As a maintainer, I want entity keys written only by Python, so that cross-runtime key drift is impossible rather than merely tested for.
48. As a maintainer, I want the read log to be the one part of the tier with retention, so that facts are kept and lookups are not.

## Implementation Decisions

### Substrate and ownership

Episodic memory lives in the Postgres instance Vigil already runs. `agent_events` stays the agent layer's, single-writer by construction. The episodic tables are the Python domain's, reached over the existing backend-tool bridge so schema knowledge stays in one language. Only Python ever writes an **Entity Key**, so the TypeScript extractor's output travels as candidate data and never as a stored key.

### Tables

Five, plus one for reads.

**Sightings** — what an investigation observed. One row per `(entity_key, investigation_kind, investigation_id, source_system)`, carrying hit count, an attacker-influenceable flag aggregated over the evidence in the group, the observed window, and the investigation's conclusion time. Never one row per evidence record: growth tracks hunts, not telemetry.

**Verdicts** — what an investigation concluded, one per **Hypothesis**. Carries `hypothesis_id` (stable, not the prose), outcome, rationale, subject entities, an attacker-influenceable-only flag, **Trust**, `concluded_at`, the observed window, and `window_source`. Unique on `(investigation_kind, investigation_id, hypothesis_id)`.

**Verdict sources** — one row per `(verdict, source_system)` carrying **Stance** and **Source Tier**. Replaces a flat corroborated list, which cannot express direction. `source_system` is memory's own column, not a foreign key into either producer: a hunt-derived Verdict fills it from the **Ledger**'s `source_system`, a Case-derived one from the `data_source` of the Case's Findings. Two vocabularies land in one column, which is why the tier map has to cover both.

**Declared Gaps** — questions an investigation never gathered evidence for. Carries a disposition describing why nothing was gathered, a human-readable reason, the entities the hypothesis named, and `concluded_at`. No activity window, which is the reason it is not a Verdict row.

**Distil markers** — one row per processed investigation, carrying origin and distil version. The only record that an investigation was processed, so it cannot be derived from the presence of rows.

**Read log** — one row per read of memory: caller kind, caller id, keys queried, rows returned, ranking parameters, timestamp. Holds reads rather than facts.

No column is nullable. An empty list means known-to-be-none; there is no unknown state to represent.

### Investigation identity

Everything is keyed by `investigation_kind` + `investigation_id`, never by `run_id`. Kinds are `hunt`, `case` and `analyst`. A run-keyed schema cannot represent a Case-authored Verdict, which the writer split requires.

### Writers

| Writer | Writes |
|---|---|
| hunt run | Sightings, Verdicts, verdict sources, Declared Gaps |
| case closure | a Verdict and its sources only |
| case reopening | nothing — it withdraws what the closure wrote |
| Python agents, chat | nothing — read only |

A Case closure is a conclusion, not an observation; what was observed were its Findings. Chat never writes: an analyst thinking aloud is not a Verdict, and letting speculation reach memory is the promotion of prose to fact ADR 0015 forbids.

### A Case is a Hypothesis

Opening a Case asserts that the activity is real and malicious; closing it answers that.

- `hypothesis_id` = the case id; the statement is the case title
- `closure_category` maps: `false_positive` → false positive, `resolved` → proven, `unable_to_resolve` → inconclusive, `duplicate` → no Verdict
- rationale falls back through false-positive reason, root cause, executive summary, closure notes, then empty — empty is a known absence, not a null
- **Trust** is `analyst` when a person closed it, `agent` when the daemon did
- the activity window comes from the min/max timestamps of the Case's Findings, whose `timestamp` and `data_source` are both non-null; where the Case has no Findings, its own open/close dates stand in and `window_source` records `asserted`
- every source on a Case-derived Verdict takes **Stance** `supports`, because the Case asserted the activity was real. A false-positive closure is therefore a clean record of every one of those sources having been wrong, which is the calibration signal, arriving from live operation

### Trust and Source Tier are two axes

They were one ordered list (`analyst › telemetry › agent › feed`) and that was incoherent: telemetry observes and a feed asserts, but neither concludes, so two of the four values could never appear on a Verdict.

- **Trust** — who concluded: `analyst` or `agent`
- **Source Tier** — what the source is: `telemetry` (observed our estate), `feed` (asserted about the world), `not_evidence` (neither)

Memory owns the source-to-tier map and stamps the tier onto the row at write time, never joining at read time — an integration removed or recategorised later must not retroactively change how a past Verdict was corroborated. Unknown sources resolve to `feed` and are logged. Sandbox detonation counts as `feed`: a real observation, but of an artifact rather than of the estate, so two sandboxes agreeing is not two independent looks at the environment. `not_evidence` on a Verdict is a defect, not a weak row — `attack-layer` and `security-detections` are reference, and citing one as corroboration is a run treating a rulebook as an observation.

The existing category data is not usable as-is: `integration_configs.integration_type` is nullable and usually unset, the compatibility service covers about half the servers, and the console's `MCP_CATEGORIES` is complete but is a display grouping in TypeScript.

**The map is keyed twice, because the two investigation kinds name sources differently.** A hunt names a telemetry domain: `attributeSource` (`services/agent/workflows/hunt/controller.ts`) collapses any worker label outside the playbook's `data_domains` to `undeclared`, preserving the original in `payload.claimed_source_system` — written in one place and read nowhere. A Case names a vendor pipeline, through the `data_source` of the Findings it groups. An earlier draft of this section grounded the map in `findings.data_source` alone, which covers the Case path and leaves hunts — the spine — unserved.

Both vocabularies are now enumerated against live data. `findings.data_source` is not free text: nine slugs, `loglm` at 98% of rows and `firewall`/`proxy`/`flow`/`edr`/`dns`/`email`/`endpoint`/`siem` behind it, so **no normalisation job stands between this map and Source Tier**. Hunt sources are the shipped playbook's three domains, the three every live hunt actually declared (`cloud_audit`/`identity`/`endpoint_process`, which appear in no repo file — a spec is reaching the runtime from outside the tree, worth chasing separately), `undeclared`, and the harness's own `critic`/`operator`/`dispatcher`, which reach the ledger uncollapsed because `attributeSource` filters on `provenance === "worker"`. Every value in both sets is `telemetry`, so the map discriminates nothing today — it earns its place as the guard that stops a rulebook being cited as an observation, and as the seam a `feed` source arrives through later. Nothing currently reachable can produce a `feed`-tier hunt source, because workers are instructed to name domains and not vendors; making one possible is a harness contract change, and it bounds how much #731 gets out of Source Tier rather than whether this map can be built.

### Verdicts name subjects only

Extracted from the Hypothesis statement, typically one to three. A Case names its subjects through its **IOCs** instead — already typed, so no extraction runs; see ADR 0016's #733 amendment for why, and for the two bounds that come with it. Not the entities its evidence touched — the committed fixtures put that at 4, 4, 7, 38, 55, 55 and 76 per hypothesis, mostly shared infrastructure. Those remain reachable through Sightings as *seen during a run that concluded X*, which is the weaker and truer claim. Full rationale in ADR 0016.

### Hypothesis status mapping

| Status at terminal | Writes |
|---|---|
| proven / disproven | Verdict, same outcome |
| inconclusive | Verdict if evidence was gathered, else Declared Gap |
| active | same test |
| parked | Gap, deprioritised |
| handed_off | Verdict, outcome `handed_off` |

`handed_off` is terminal for the hunt but not an ending of the claim, and it carries evidence, a window and sources — so neither "never looked" nor "failed to conclude" is true of it. It ranks up like a Gap, which is why the rank-up rule is stated over open questions rather than over one table. The Case that receives it writes its own Verdict later; the two rows together are the trail.

At run level, `aborted` writes nothing. `budget_terminated` and `data_starved` write normally: running out is an outcome, crashing is not.

### Read path

At run start: seed keys from the spec with the harness's typed extractor (no model call), exact-join Sightings, Verdicts and Gaps, apply a per-key cap before the overall token budget, journal the rows as a **Ledger** event, render into the frozen prefix.

Two constraints that are easy to miss. Every recall query needs a **total order** — `LIMIT` over a partial order lets Postgres return a different set on identical data, which surfaces as a replay diff rather than an error, so ties break on the primary key. And `concluded_at <= run_start` is a freshness filter, not a substitute for the journaled rows: the **Distil** polls, so an investigation that ended Monday can be written Wednesday carrying Monday's date, inside the predicate and absent from the original read.

The per-key cap is a lateral, not a plain `LIMIT` — otherwise one entity present in every hunt consumes the entire budget.

Mid-run: `recall_entity(entity_key)` as a backend tool, resolved by the existing tools router ahead of MCP servers, landing in the prompt tail so the prefix is undisturbed. Journaled as an ordinary tool call, which is why only the run-start read needs its own event kind. Grants are per-role config: workers get exact lookups, narrative search is the lead's alone.

Ship one tool. `prior_investigations` and `attribution` are deferrable — attribution is a Verdict with an actor in it, and an as-of parameter belongs on every read rather than being a tool of its own. Each additional tool costs prompt surface, a grant per role, and a choice the model can get wrong.

### Write path

A terminal event does not write memory. A Python job polls for terminals with no marker, using the existing partial index on the ledger. Poll over push: no change to the agent layer, a lost trigger becomes a late write rather than a missing one, backfill is the same code path exercised constantly, and nothing is waiting — memory is read at the *start* of the next run. The Distil finds terminals itself rather than being told by a supervisor: memory that waits stops being written the moment the teller is down.

The job reads the harness's already-typed conclusions and maps them to rows. It does not re-derive them: the fold is TypeScript, and a second implementation in Python would drift while only one is gated. A field the Distil needs and cannot find is a contract change to request, not something to reconstruct.

**Idempotency is delete-then-insert, scoped to the investigation, inside one transaction — not `ON CONFLICT DO UPDATE`.** Upserting fixes rows that still exist and does nothing about rows that should not: bump the version, re-derive a run whose new logic yields six Sightings where the old yielded eight, and two stale rows survive indistinguishable from real ones. Counts are computed and set, never incremented.

The marker is written in the same transaction as the rows. Split them and a crash between either double-writes the investigation or marks it done when it is not.

This makes append-only a promise *across* investigations — nothing an investigation concluded is rewritten by a later one — while an investigation's own rows are replaceable as a set. Which is a further reason recall journals what it returned: a legitimate re-derive can change what an as-of query answers.

### Ranking inputs

The ranking itself is the harness's, not this spec's. What this spec owes it: outcome, source count by **Stance** and **Source Tier**, **Trust**, `concluded_at`, the observed window and its `window_source`, and per-entity counts of open questions.

The Gap boost comes from accumulation on an entity, not from being a Gap. The fixtures leave 14 of 18 hypotheses open at terminal, so Gaps are the common case — six open questions across four runs is a host nobody has finished investigating; one is an ordinary run ending. Counted per entity rather than per question, because deciding whether two runs asked the same question means comparing prose, which never enters the ranking path. Counted raw initially; normalising against how often an entity is seen at all is held in reserve for when a resolver floats to the top.

Ranking parameters are copied into the recall event because a RunSpec records the arch by name and not by version. The general fix — an arch content hash in the spec — is the harness's and applies to more than memory.

### Live defects on this path

`get_shared_iocs()` intersects two in-memory sets, so cross-investigation correlation resets on daemon restart. Replace with the indexed join against `shared_iocs`, which already exists with no reader or writer. This is the same join shape as everything downstream, which is why it comes first.

The write-path failure swallows are what make a dead store read as healthy to the daemon and to chat, the two surfaces nobody watches during a run. Memory writes raise and retry.

Their failure state is not in the marker table. A marker is keyed by investigation, and the two commonest failures happen before there is an investigation to key on — an unreadable fold has only a run id, and a refused payload is frequently refused *because* it carries no investigation id. So failure is its own table, keyed by the run for a hunt and the case for a Case, and it is what paces the return: absence means not yet reached, a row means tried and failed, and an attempt count in the dozens is a query rather than a hunch. A refusal waits at the far end of that same column rather than under a second rule, because what this side will not map does not become mappable by being read again. Nothing is ever abandoned on a count — a count cannot tell a store that will come back from one that will not, so a ceiling would have to choose between giving up on the first and hammering the second — and a bump of the mapping version re-offers everything that failed under the old one.

### Evals

A snapshot is a Postgres schema holding a copy of the tables, selected by `search_path`. Not an `as_of` filter over the live tables — for the same reason recall journals its rows. An empty schema is the control, and the difference between empty and populated over the same hunts is what memory is worth. Snapshots are named by date and kept rather than overwritten: old snapshot with new code measures the code, new snapshot with new code measures the system.

A snapshot does not cover narrative search, whose corpus lives outside Postgres. Until that is handled, "we froze memory" is true of the exact-join tier only.

## Testing Decisions

A good test here calls in at the same place a real caller does, with real inputs, and asserts what a real caller would see. It does not know how the query is written, where the extractor lives, or which table the marker is in — all of those should be free to change without a test failing. Tests that assert on internal shapes will break on every rename and will not tell you the feature works.

**Two seams.**

**The read seam is `execute_backend_tool`.** It already exists as the single dispatch point for backend tools and has prior art in `tests/unit/agents/test_tools_router.py`. Calling `recall_entity` through it with known rows in the database exercises registry wiring, key normalisation, the per-key cap, the token budget, the dropped count and the read log in one call — and it is exactly what an agent does.

Worth covering at that seam: an entity with history returns it; an entity with none returns an empty result rather than an error; a key that differs only by case or defanging finds the same rows; an entity with more Sightings than the per-key cap returns the cap and reports the rest as dropped; a run-start read of forty keys stays inside the token budget and names what it dropped; two identical reads over unchanged data return the same rows in the same order.

**The write seam is one `distil(investigation_kind, investigation_id)` call.** Input is a **Ledger** already in the database; output is rows plus a marker. One call covers status mapping, subject extraction, **Stance**, **Source Tier** stamping and window derivation. Called twice, it covers idempotency — and called twice with a bumped version after a derivation change, it covers the stale-row case that `ON CONFLICT` would miss.

Worth covering at that seam: a run with proven and disproven hypotheses writes Verdicts; one with open hypotheses and no evidence writes Gaps; one with evidence but no conclusion writes inconclusive Verdicts; `handed_off` writes a Verdict with that outcome; an aborted run writes nothing at all; a run that concluded nothing still writes a marker; a second call changes nothing; a Case closure with Findings writes an observed window and one without writes an asserted one; a Case with no Findings at all still writes a Verdict, with an asserted window and no sources — an earlier draft of this line said it wrote none, which contradicts user story 22 and the #733 acceptance criteria, and the criteria win; a Case reopened after closing has its Verdict withdrawn.

**Not seams.** The poll loop is a query and a for-loop over the write seam. The read log is asserted through the read seam. The snapshot export's correctness is that the copy matches. The TypeScript `Memory` port is the harness's call site.

**One fixture problem worth planning for.** The write seam needs a **Ledger** in Postgres to be worth anything. The ten committed ones are gzipped JSONL for the vitest suite, so using them from pytest means a loader — and eight of the ten never reached a terminal, so they exercise the Gap path and little else. Getting one good terminal fixture in is most of the work behind the write seam's tests.

**The gate that matters most is not a unit test.** A recorded run whose prefix carries recalled rows, added to the fold-equivalence suite, is the acceptance test for the whole feature. Without one, the gate passes without ever exercising memory and every rule in ADR 0015 is documented but unenforced.

## Out of Scope

**The reference tier.** ATT&CK, Sigma and threat feeds already exist in `core/threat_intel/` and `data/taxonomy/`, populated from real sources. Untouched.

**Calibration.** Last, not never, and a read rather than a store — a query over Verdicts and their sources once the response track has produced outcomes. Nothing to build now beyond recording **Stance** and outcome, which this spec does. Note the circularity in the plan artifact: Track 3 is described as using calibration to justify actions, while calibration needs to know how actions turned out. It breaks by Track 3 shipping without it and generating the labels it will later read.

**Seeding.** An MVP deployment has no back catalogue, so importing history proves nothing about the read path. Deferred, not designed away — when it returns, a seed batch is an Investigation like any other, deletable by id.

**Narrative search and the zeromem integration.** The engine exists; wiring it in is this side's work but a separate change. This spec's exact-join tier ships and is useful without it. Two things it needs that do not exist yet: a text embedding model (`findings.embedding` is behavioural, not text) and ranked lexical retrieval, which stock Postgres lacks — `pg_trgm` is trigram substring matching, not BM25. Options are Postgres FTS, a non-stock extension, or a sidecar.

**Chat's own conversational memory.** A strong fit for zeromem — better than the job assigned to it here, since its own benchmarks are conversational — but it does not address hunts re-deriving context, and it raises a sharper privacy question. Separate corpus, no path into these tables, and whether it is per-user or shared should be decided before it is built rather than after.

**Retiring MemPalace.** In scope for the project, out of scope for this spec, and ordered after it: pull the store before the replacement is proven and the Python agents lose memory with nothing in its place. It touches the submodule and its requirements entry, the MCP registration, the daemon's use of it, chat's transcript store, `mcp-config.json`, `env.example`, Helm values, both Dockerfiles, `start.sh`, the setup scripts, four test files and six console references — and takes `.gitmodules` to zero entries.

**Anything graph.** Our own measurements had the graph view losing to plain keyword search on three corpora — LoCoMo 0.374 against 0.580. Activation is multiplied by query similarity at every hop, so it can only re-rank what the lexical and dense signals already surfaced; it cannot reach a relational neighbour worded unlike the query, which is the only reason to want a graph. SOC correlation is one to two hops. The result is not neutral toward this design: the graph view failed *because* it approximated a join.

**Bitemporal machinery.** Append-only gives as-of queries as a predicate on `concluded_at`. The transaction-time column, the as-of query layer and upsert semantics on three tables all evaporate.

**Aliasing.** Two keys naming one thing are linked, never merged, and the link is symmetric with no canonical side. Deferring is safe precisely because of that choice.

**Consolidating the existing IOC stores.** `shared_iocs`, `case_iocs` and `threat_indicators` overlap today and this spec adds to the pile rather than unifying them. Extending a live table the daemon uses would turn a self-contained change into a migration, and append-only cannot be retrofitted onto rows that are already upserted. Real debt, named rather than assumed away.

**The ranking itself, and the fleet projection.** Both the harness side's. The fleet projection is a separate store: keyed by run, disposable, read continuously, and it must hold status — which episodic memory must not, because status on an entity is memory deciding. It may read these tables and never writes them.

## Further Notes

**The skip is refused deliberately.** "Confirmed false positive three times, do not look again" is the single largest efficiency win a memory tier can offer, and the earlier plan called that record the highest-ROI row in the system. It is declined because it is also an adversary's cheapest hiding place — where a system does not look is itself information, and it is information an attacker can act on. What is offered instead is the host at position one on iteration one rather than iteration thirty. Everyone reviewing this will ask for the skip; the answer is ADR 0015, not a cost estimate.

**Two contracts to settle before either side builds**, about a page: the recall event payload, and the tool signatures. Everything else is internal to one side, and a mismatch fails silently as "no history". That is now the only silent failure on this path: a Distil that cannot read a fold, cannot map one, or cannot write one leaves a row saying which. A contract mismatch that yields a readable, mappable, writable payload of the wrong shape leaves nothing, and the gate in #737 is what covers it.

**The ranking is the harness side's and it grew during design.** Accumulation-per-entity for Gaps, three-valued **Stance**, `handed_off` ranking up like a Gap, and a separate budget slice so Gaps cannot crowd out conclusions. None of that was in the original handoff, and every rule in ADR 0015 executes in their code — which makes that ADR a handoff artifact rather than documentation.

**Sequencing.** The earlier plan argued memory should land before concurrent hypothesis branches, on the grounds that evals take one new source of nondeterminism at a time. The current arrangement runs them in parallel. The frozen snapshot defuses the memory half; nothing defuses branch ordering.

**Order of work.** Fix the daemon's correlation defect; agree the two contracts; tables; the read seam and its tool; the Distil and its poll; the eval snapshot export while the schema is fresh. Then the harness side's recall call, Ledger event and ranking, and finally a recorded run carrying recall added to the fold-equivalence gate. Everything up to the harness handover is one side's work, so a coordination delay slows the payoff without blocking the build.

**One thing left to check against live data before building.** How many entities a real closed Case names, which is the same question ADR 0016 answered for hunts and has not been answered for cases.

The other — what `findings.data_source` actually contains — is answered above: nine slugs, no free text, no normalisation job. That check also turned up the reason the tier map is keyed twice rather than once.
