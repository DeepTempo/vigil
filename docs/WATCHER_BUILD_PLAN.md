# The Watcher — Build Plan (Slice 1: alert → evidence)

> Companion to [WATCHER_SCOPING.md](WATCHER_SCOPING.md) (the *what* and *why*).
> This is the *how*: an input→output build, one stage at a time, each with an
> acceptance test and a running status log so it stays clear what was done and why.
>
> Branch: `feat/watcher-loop`.

---

## The framing decision that shapes everything

The TS hunt engine (`services/agent/workflows/hunt/`) **already** does the hard part
of Slice 1: it forms a board of hypotheses, fans out ≤4 read-only workers to gather
evidence, runs a disconfirmation critic against a seeded null, and records every
for/against ruling in a replayable ledger.

But **the hunt Lead does not invent hypotheses** — it only *tests* ones it is handed.
Hypotheses are seeded at start from the run spec (`controller.ts` `startHunt`,
`provenance: "hunt_spec"`), and a hunt with nothing real to test is refused
(`resolve_hunt` / `execute_workflow`). Today a **human** authors that hypothesis (plus
scope and context) in the console; `resolve_hunt` reads it from workflow metadata.

**So the Watcher's net-new job in Slice 1 is to be that human.** It turns an *alert*
into the *hypothesis + context* a person types today, then rides the existing
enqueue → worker → projection plumbing. That is one net-new reasoning step; the rest
is wiring.

```
  alert (finding dict)
        │
        ▼
  ┌─────────────────────────┐   A. Hypothesizer (NET-NEW)
  │ "what attack could this │      the Watcher plays the human:
  │  be?" → hypotheses      │      alert → hypotheses + scope + context
  └─────────────────────────┘
        │
        ▼
  ┌─────────────────────────┐   B. Spec builder (mechanical)
  │ resolve_hunt-shaped      │     mirror the dict resolve_hunt emits
  │ hunt request             │
  └─────────────────────────┘
        │
        ▼
  ┌─────────────────────────┐   C. Enqueue + reconcile (REUSE)
  │ build_start_job(hunt)    │     BullMQ agent-runs → TS worker →
  │  → runHunt → projection  │     read_projection
  └─────────────────────────┘
        │
        ▼
  hypotheses + evidence for/against   D. Surface (thin view over projection)
```

Slice 1 **stops here** — no decision, no response action, no cross-alert memory.
Those are later slices (see Scoping §6).

---

## Where this cuts into the daemon

The replacement seam is intake. Today:

- Processor gate `_evaluate_for_response` (`services/daemon/processor.py:773`) decides a
  finding is worth acting on and drops it on `orchestrator.investigation_queue`.
- Intake loop `_create_investigation_for_finding` (`services/daemon/orchestrator.py:272`)
  picks a **fixed playbook** via `select_workflow(finding)` (`plan_generator.py:69`) — a
  dumb deterministic `if severity==... return "incident-response"` map — then materializes
  an `investigate` run.

Slice 1 adds a **parallel path** off that same queue: instead of `select_workflow` →
`investigate`, the Watcher does Hypothesizer → hunt spec → `hunt` run. We do **not**
rip out `select_workflow` yet; we add the Watcher path behind a flag so the existing
daemon keeps working and we can A/B the two on the same alert.

---

## Reference: what stage B must produce

`resolve_hunt` (`core/workflows/playbook_resolver.py:369`) reads these off workflow
metadata today. Stage A must produce the *content*; stage B packs it into this shape:

| Field | Source today (human) | Source in Watcher (stage A) |
|---|---|---|
| `hypotheses` | typed in console | synthesized from the finding — **required, ≥1** |
| `attack_techniques` | workflow metadata | from `finding.mitre_predictions` keys |
| `data_domains` | workflow metadata | inferred from `finding.data_source` / entity types |
| `scope` | workflow metadata | from `finding.entity_context` (ips, hosts, users) |
| `objectives`, `narrative`, `directives` | workflow body/metadata | short context derived from the finding |

`config` (model, budgets, bound tools, thresholds, `hypothesis_loop`) is produced by
`resolve_hunt` itself from capability binding — **we reuse it unchanged**.

---

## Stages

Each stage is independently runnable and has an acceptance test. Don't start the next
until the current one's test passes.

### Stage A — Hypothesizer (net-new)

- **Goal:** a finding dict → 1–N attacker-intent hypotheses + `attack_techniques`,
  `data_domains`, `scope`, and a short context/narrative — the artifact a human
  authors today.
- **Input:** the normalized finding dict (`poller.py` shape: `entity_context`,
  `mitre_predictions`, `severity`, `data_source`, `title`, `description`,
  `anomaly_score`).
- **Output:** a typed `WatcherHypothesisSet` (Pydantic) carrying the fields in the
  table above.
- **Files (planned):** `services/daemon/watcher/hypothesizer.py` (new),
  schema alongside it. LLM call via `services/llm_router` / the sanctioned client
  factory — never a raw `Anthropic()`.
- **Acceptance test:** feed 3–5 real BOTSv3 alerts; each yields ≥1 concrete,
  testable hypothesis (not "something suspicious happened") with technique IDs that
  match the alert's `mitre_predictions`. Eyeball for intent quality. Unit test with a
  fixed finding fixture asserts schema + ≥1 hypothesis.
- **Design refinement (owner-steered):** the Hypothesizer reasons over an
  *enriched* finding, not the raw alert — it gathers **reputation** (VT/Shodan/feed
  off the finding) and builds **scope** from entities. Triage's
  `category`/`recommended_action` are deliberately **not** fed in (premature guess).
  **Asset context** (host role / user privilege) has no source and is an accepted
  gap — the prompt tells the model it is blind there. **Cross-alert memory**
  (prior-investigation history) is deferred — see the note below.
- **Status:** ◑ built + unit-tested. `schemas.py` (contract) +
  `hypothesizer.py` (context gather → prompt → parse → validate) +
  `tests/unit/daemon/watcher/test_hypothesizer.py` (fake gateway, all green).
  **Still pending:** the real-alert eyeball —
  feed live BOTSv3 alerts through a running stack and judge seed quality (that
  test decides whether the LLM seed earns its keep vs. a minimal deterministic
  seed). Parked: renaming the `submit_triage` call for clarity.

### Stage B — Spec builder (mechanical)

- **Goal:** `WatcherHypothesisSet` → the exact `(playbook_yaml, config_yaml)` pair
  `resolve_hunt` emits, so the TS worker can't tell a Watcher hunt from a console one.
- **Files (planned):** `services/daemon/watcher/spec.py` (new). Reuse
  `resolve_hunt`'s `config` half unchanged; only synthesize the `playbook` dict from
  stage A's output.
- **Acceptance test:** golden-diff — build a request from a fixture finding, diff the
  YAML against a hand-authored console hunt for the same scenario; fields line up,
  hypotheses present, `hypothesis_loop: true`.
- **Contract finding (reshaped this stage):** the hunt has a per-run door for
  **only `hypotheses`** (+ iterations/budgets). `attack_techniques`, `data_domains`,
  and `scope` have **no per-run channel** — the agent contract sources them solely
  from a stored hunt definition's front-matter (inline spec YAML is read as a *file
  path*; job `overrides` reject everything but budgets/runtime; DB workflows drop
  the fields and resolve as `compose`). **Owner decision:** don't fight it — fold
  those three into the **target-context prompt** the hunt already reads (keeps the
  information, loses only worker-schema enum-narrowing). So Stage B is a pure map
  `WatcherHypothesisSet -> execute_workflow("threat-hunt", parameters)` — the exact
  console call, machine-driven.
- **Status:** ✅ built + unit-tested. `spec.py::build_hunt_parameters`
  (`hypothesis` per-run; `finding_id`; `context` = narrative+techniques+domains+
  scope) + `tests/unit/daemon/watcher/test_spec.py` (7 tests). Includes a guard
  that emitted hypotheses survive `execute_workflow`'s `_not_a_claim` gate, so a
  real hunt won't be refused.

### Stage C — Enqueue + reconcile (reuse)

- **Goal:** hand the request to the existing kickoff path and read the run back.
- **Reuse as-is:** `build_start_job(run_id, "hunt", request)` (`core/agents/queue.py:50`)
  → `enqueue_run` → BullMQ `agent-runs` → TS `runHunt` → `read_projection(run_id)`
  (`core/agents/projections.py:40`). `run_id_for` keeps it deterministic.
- **Files (planned):** the Watcher path in a new
  `services/daemon/watcher/loop.py`, wired off `investigation_queue` behind a config
  flag (`WATCHER_ENABLED`, default off).
- **Acceptance test:** with live Splunk + BOTSv3 (see [BOTSV3_HUNT_SETUP.md](BOTSV3_HUNT_SETUP.md)),
  a real alert enqueues a hunt that the agent layer picks up and drives to a terminal
  outcome; `read_projection` returns a populated ledger (hypotheses, evidence,
  dispatches). This is the first true end-to-end run.
- **Status:** ◑ module built + unit-tested. `launch.py::launch_hunt`
  (rides `WorkflowsService.execute_workflow("threat-hunt", params)` — the console's
  own enqueue path) + `read_hunt` (wraps `read_projection`) +
  `tests/unit/daemon/watcher/test_launch.py` (6 tests, fake WorkflowsService +
  fake reader). The mock LogLM has a `--launch` flag that fires it end-to-end.
  **Still pending:** an actual live run — needs DB+Redis (up), the agent layer
  (`scripts/agent_up.sh`), and a *stable* Splunk with `telemetry_search` bound, or
  the hunt is data-starved. Not yet wired as the daemon intake loop behind
  `WATCHER_ENABLED` (that's the productionization step after the live run proves out).

### Stage D — Surface output (thin view)

- **Goal:** present Slice 1's output: each hypothesis with the evidence gathered
  for and against it.
- **Reuse:** the projection already carries `hypotheses`, `evidence`, `links`
  (for/against rulings). `workflows_router.py:439` already attaches
  `read_projection` to a row — mirror that read.
- **Files (planned):** a small read in the Watcher loop that logs/persists the
  for/against summary; console view is optional for Slice 1 (log-level acceptance is
  fine).
- **Acceptance test:** for a known BOTSv3 attack, the surfaced output shows the
  hypothesis that matches the real attack accumulating supporting evidence and the
  null (benign) explanation losing ground — i.e. the ledger's for/against is legible.
- **Status:** ☐ not started

---

## Guardrails held for Slice 1

- **No response actions.** The hunt's only terminal verb is `HANDOFF_IR`; we do not
  wire `ActionType` / `approval_service` yet (that's a later slice + the net-new
  consequence-tier map).
- **No cross-alert memory.** Each alert → one independent hunt. Prior-investigation
  history (`shared_intel.check_overlap`), standing hypotheses, entity-watch, decay,
  and the attack-intent consolidation axis are all deferred (Scoping §6 Defer /
  Build). The Hypothesizer no longer wires any memory source — reputation
  enrichment (VT/Shodan, a per-alert fact) is not memory and stays.
- **Existing daemon untouched.** Watcher path is additive behind `WATCHER_ENABLED`;
  `select_workflow` → `investigate` still runs when the flag is off.
- **Config via the sanctioned channels** (`core.config` / `core.secrets`), no
  `os.getenv`; LLM via the client factory, not raw `Anthropic()`.

---

## Status log (what was done & why)

- **2026-08-31** — Plan created. Mapped the three seams (daemon intake, TS hunt
  engine, approval/consolidation) via read-only exploration; confirmed Slice 1 is
  mostly wiring around one net-new reasoning step (the Hypothesizer). Branch
  `feat/watcher-loop` cut from `feat/hunt-runnable-from-the-console` so the working
  BOTSv3 hunt harness is available for Stage C/D validation.
