# The Watcher — Role & Infrastructure Scoping

> Status: **scoping only.** This defines what the Watcher *is*, the infra it
> *needs*, what it *reuses*, and what is explicitly *out of scope*. It is not a
> build plan. Decisions below were settled in a design-tree interview; open items
> are called out in [Dependencies](#dependencies--open-items).

---

## 1. What the Watcher is

The Watcher is the **autonomous decision core of the daemon** — it replaces the
current `Orchestrator` intake logic. Where intake today picks a *fixed playbook*
(`select_workflow(finding)`, no reasoning), the Watcher **forms a hypothesis about
attacker intent, dispatches read-only delegates to confirm/disprove it, evaluates
what comes back, and decides which response — if any — should proceed.** It is the
software analogue of a SOC analyst reacting to an IOC: evaluate evidence, form a
belief, direct investigation, act within a safe blast radius.

It is a **stateful** loop: it carries open hypotheses and entities-under-watch
*across* alerts, not just within a single run.

---

## 2. Settled decisions

| # | Decision | Outcome |
|---|----------|---------|
| Autonomy | How much acts without a human? | **Autonomous within a blast radius.** Reversible/low-consequence actions auto-execute; high-consequence always escalates. Full no-human is a config toggle, not the default. |
| Trigger | What wakes it? | **Both** — event-driven on inbound alerts *and* a periodic sweep for slow-burn patterns and cross-entity consolidation. |
| Delegate | What is a delegate? | A **read-only, information-gathering sub-agent** the Watcher spawns to feed itself evidence. **≤ 4 delegates, depth 1.** Delegates gather; the Watcher acts. |
| State | Stateless or stateful? | **Stateful.** Standing hypotheses + entity-watch set survive across triggers. |
| Tier | Which process? | **Python daemon.** The reasoning/delegates are dispatched over the existing BullMQ `agent-runs` seam. |
| vs Orchestrator | New / parallel / replace? | **Replaces** the orchestrator's intake decision *and* its review decision. Keeps supervision as guardrail infra (with caveats below). |
| Consolidation | Reuse or build? | **Reuse** `shared_intel` entity/IOC indices; add a thin **attack-intent** axis (cluster by hypothesized MITRE technique / campaign) on top. |
| Gate | How do actions gate? | **Consequence-gated, then confidence-gated.** Consequence sets the ceiling (high-consequence never auto-runs regardless of confidence); confidence gates the low-consequence actions so reversible actions don't fire on a weak hunch. |
| Lifecycle | What closes a hypothesis? | **Resolution or decay.** Confirmed/disproven closes it; a TTL ages out untouched items so the stateful working set — and every sweep — stays bounded. |
| Evidence injection | Live or at-tick? | **Live**, reusing the existing directive/inbox path (see §6). |
| Review loop | Keep it? | **Dropped.** Its mechanical `completeness ≥ 0.8` check is not a real evaluation. Evaluating a delegate's return *is* a step in the Watcher's own decision cycle. |

---

## 3. Responsibilities

- Form hypotheses about attacker intent from incoming alerts and standing state.
- Prioritize and dispatch read-only delegates to confirm/disprove those hypotheses.
- Evaluate response actions proposed by a completed run and weigh their
  consequences before allowing them to proceed.
- Consolidate alerts by entity (reuse) and by attack intent (new thin axis).
- Introduce new evidence into active investigations as it arrives.
- Keep delegates on-objective — detect and correct purpose drift.

---

## 4. Architecture — how it fits the daemon

The daemon's `Orchestrator` runs three loops today: **intake**, **supervision**,
**review**. The Watcher reshapes them:

- **Intake → replaced.** `select_workflow(finding)` (pick a fixed playbook)
  becomes: *form a hypothesis → dispatch delegates → decide.* The direct-playbook
  path becomes one option the Watcher can choose, not the only behavior.
- **Supervision → kept as guardrail infra, trimmed.** Approval-raising and
  cross-correlation stay. **Stale-kill and cost-kill are redundant** for the
  Watcher's own delegates: the **hunt controller already enforces per-delegate
  iteration/cost budgets** internally. Daemon-level stale/cost supervision for
  *other* (non-hunt) agents is **out of scope** for now.
- **Review → dropped.** See the decision table. The Watcher's own evaluation
  replaces the completeness checkbox. Only the useful side-effects of the old
  review path survive (create approval action, persist to memory when that lands,
  trigger cross-correlation) — now fired by the Watcher's judgment, not a %.

The reasoning engine itself is **repurposed, not lifted wholesale**, from the TS
hunt loop (`services/agent/workflows/hunt/`) — a mature Lead/Workers/Critic engine
that already forms hypotheses, fans out to ≤ 4 depth-1 read-only workers, runs a
**disconfirmation critic** and a seeded **null hypothesis**, and keeps a replayable
evidence **ledger**. This is a new Watcher loop that reuses those components; it is
a build to be done with the owner in the loop, not a rename of the hunt engine.

---

## 5. Delegation & safety model

**Delegation.** ≤ 4 delegates, depth 1. Delegates are read-only info-gatherers
dispatched over the BullMQ `agent-runs` seam the daemon already uses. Depth-1 means
a delegate cannot itself spawn Watchers. Purpose-drift oversight reuses the hunt
loop's coverage/critic pattern (every observation must be ruled for/against each
active hypothesis, including the null).

**Two-axis gate.** An action executes autonomously **only if** its *consequence
tier* is low **and** confidence is high:

| | Low consequence (reversible) | High consequence (isolate_host, disable_user, …) |
|---|---|---|
| **High confidence** | Auto-execute | **Escalate** |
| **Low confidence** | **Escalate** | **Escalate** |

Consequence is the ceiling; confidence gates the auto-execute corner. This needs
one net-new deterministic piece: a static **`ActionType → consequence tier`** map
layered onto the existing confidence gate in `approval_service`. Everything else on
the safety path is reused.

---

## 6. Infrastructure — reuse / build / defer / out-of-scope

### Reuse as-is
- **Trigger + guardrail host:** the daemon's poll→triage→intake path, hourly/daily
  cost caps, approval-raising, cross-correlation (`services/daemon/`).
- **Reasoning components:** hunt Lead/Workers/Critic, evidence ledger,
  null-hypothesis, disconfirmation critic, ≤4 fan-out (`services/agent/workflows/hunt/`).
- **Response + gate:** `core/response/approval_service.py` (`ActionType`,
  confidence gate, `force_manual_approval` kill-switch), autonomous response
  execution.
- **Consolidation substrate:** `shared_intel` entity/IOC indices, `check_overlap`,
  `get_related_investigations`, case-linking.
- **Live evidence injection:** the **directive/inbox** system —
  `POST /agent-runs/{id}/directives` queues a `note` (free-text observation) or
  `lead` (actionable lead); the running Lead drains it at the next iteration
  boundary and folds it into its digest. The Watcher pushes new evidence this way.
- **Kickoff/reconcile plumbing:** `build_start_job` / `enqueue_run` → BullMQ
  `agent-runs` → TS worker → `read_projection` reconcile.

### Build (net-new)
- The **Watcher loop** in the daemon (replacing intake): hypothesis formation over
  alerts/entities/cases, delegate prioritization, evaluate-and-decide cycle.
- Lifting hunt-style hypothesis reasoning **up a tier** — over alerts/entities/cases
  rather than intra-hunt telemetry only.
- The **decision → response bridge**: today a hunt can only `HANDOFF_IR`; the
  Watcher must drive `ActionType` responses through `approval_service`.
- The static **`ActionType → consequence tier`** map (the one net-new safety piece).
- The thin **attack-intent** consolidation axis on top of `shared_intel`.
- **Hypothesis/entity decay** (TTL) over the standing state.

### Defer (dependent on a broader decision)
- **Watcher memory / standing state model.** The Watcher needs persistent state for
  hypotheses that span alerts and outlive any single `Investigation` — nothing today
  holds that. Its concrete shape is **deferred to the broader all-agent memory
  conversation** rather than designed here.

### Out of scope (now)
- Reworking daemon-level stale/cost supervision for **non-hunt** agents.
- Recursive delegation / depth > 1.
- Full-autonomy-by-default (no-human) — remains a config toggle, off by default.

---

## 7. Trigger model

- **Event:** the daemon's existing poller→processor feed *is* the event source; a
  new finding that clears intake severity wakes the Watcher.
- **Sweep:** a periodic tick re-weighs standing hypotheses, ages out decayed items,
  runs entity/intent consolidation, and catches slow-burn patterns no single alert
  trips.

---

## Dependencies & open items

1. **All-agent memory model** — blocks the concrete Watcher standing-state design
   (§6 Defer). The Watcher *needs* memory; its shape waits on that decision.
2. Owner-in-the-loop build of the new Watcher loop (explicit ask — not a
   delegate-and-forget task).

---

## Non-goals

- Not a second brain running in parallel with the orchestrator — it **replaces**
  the intake/review decision.
- Not a re-home or rename of the TS hunt engine — a new loop that **reuses** its
  components.
- Not a full autonomous responder by default — high-consequence actions escalate.
