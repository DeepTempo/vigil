# Vigil — `core/` domain structure

How code is grouped under `core/`. The reorg (epic #481) moves loose
`services/*.py` modules into named domain packages so each capability owns its
files and cross-cutting infrastructure has a deliberate home. `core/` has two
tiers: **capability domains** (what the SOC does) and a **shared-infrastructure
tier** (`storage`, `platform`) that capability domains depend on.

## Language

### Capability domains

**Finding**:
The atomic unit of security signal — one detection/alert instance ingested into
Vigil. Findings are finding-level (evidence, entity graphs, MITRE predictions
attach to a Finding), distinct from the Case that groups them.
_Avoid_: alert, event (when you mean a Finding specifically)

**Case**:
An investigation container that groups Findings with evidence, IOCs, SLA, and a
lifecycle. `cases` owns case lifecycle + anything that writes into a Case
(e.g. sandbox reports correlated into case evidence/IOCs).
_Avoid_: incident, ticket

**Source Evidence**:
Normalized, bounded evidence attached to a Finding (contract in
`docs/SOURCE_EVIDENCE.md`). A finding-level concept, not case-scoped.

**Detection** (`detections`):
Detection-*rule* sources and their management — not finding analysis. "The rules
that produce Findings," distinct from the Findings themselves.

**Response** (`response`):
Autonomous containment actions and the approval workflow that gates them.

**Threat Intel** (`threat_intel`):
External threat knowledge — STIX/TAXII feed ingestion and MITRE ATT&CK taxonomy
resolution. MITRE lookup lives here as a reusable taxonomy resolver.

**Ingestion** (`ingestion`):
Pulling *external* security data into Vigil (SIEM, Kafka, S3-dropped findings).
Distinct from `storage`: ingestion *uses* storage clients; storage never
depends on ingestion.

**Workflows**, **Reporting**, **Chat**, **Auth**:
Multi-agent playbooks; PDF/report generation; the agentic chat loop + durable
conversations; page-extension session tokens and origin trust.

### Shared-infrastructure tier

**Storage** (`storage`):
How Vigil persists and reads *its own* data — the full metadata-DB layer (ORM
`models`, the engine/session in `connection`, `DatabaseService`, the DB-backed
`config_service`), the higher-level data-access layer, DB/connection proxies, and
the S3 object-store client. A capability domain may depend on `storage`;
`storage` depends on no capability domain. There is **no** top-level `database/`
Python package and **no** `core/platform/db/` — all DB code lives here.

**Platform** (`platform`):
Process/config/runtime plumbing — local service orchestration, autostart config,
memory-palace paths, demo-data seeding, URL/SSRF safety. Not a junk drawer: a
file belongs here only if it's runtime plumbing with no owning capability.

## Relationships

- A **Case** groups one or more **Findings**
- **Ingestion** produces **Findings** and depends on **Storage** (never the reverse)
- Capability domains depend on the **Storage**/**Platform** tier; the tier
  depends on no capability domain
- **LLM** code (`core/llm/`, in flight as #485/#522) is a separate slice, not
  part of these domains

## Flagged ambiguities

- **"finding" work kept falling into `cases`.** `source_evidence` and
  `graph_builder` are finding-level, not case-level. Resolved: they belong to a
  **`findings`** domain, deferred until PR #537 (`services/findings/enrichment/`,
  issue #470) lands, then consolidated into `core/findings/` in a follow-up.
  Until then both stay in `services/`.
- **`platform` was absorbing LLM config.** `defaults.py` and `runtime_config.py`
  read as "central config" but their content is model/thinking/AI-ops settings.
  Resolved: they're **LLM-slice** files (#485), not `platform`.
- **`s3_service`: ingestion or storage?** Its purpose is sourcing findings, but
  `storage`'s own data-access layer depends on it. Resolved: **storage** (an
  object-store client), so the layering isn't inverted.
- **DB code: `platform/db/` or `storage`?** REARCHITECTURE §7 routed the
  remaining top-level `database/*.py` (models, connection, service,
  config_service) to `core/platform/db/`. Resolved (R6, epic #481): they join
  **`core/storage/`** — storage already owned the data-access layer + `db_proxy`,
  and a `platform/db/` split would only relocate the cross-domain reach
  (`core/storage/database_data_service` → top-level `database`) instead of killing
  it. No `core/platform/db/`; the top-level `database/` package is retired and its
  SQL moves to `infra/database/init/`.
