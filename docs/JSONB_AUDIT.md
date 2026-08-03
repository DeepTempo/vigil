# JSONB column audit

Classification of every `JSONB` column in the ORM as **keep** (legitimately
schemaless) or **promote** (typed data stashed in JSON, hiding structure from the
ORM, the API contract and any query). Answers issue #468.

## Method and scope

**Audited artefact: `database/models.py` — the ORM.** That is the effective
schema, because `create_all` still builds any table absent from
`database/init/*.sql`.

**The column count is 54, not the 74 in the issue title.** 54 `JSONB` column
declarations across 32 model classes. 74 appears to be a count of `JSONB`
*occurrences* in the file (69 today, and the same 69 at `8abecc2` / v0.4.0, so
nothing was deleted to explain the gap) rather than column declarations.

**Verdicts are grounded in the `Mapped[...]` annotation plus at least one real
reader or writer**, not the column name. Where a shape could not be confirmed
from a call site, the verdict says so rather than guessing.

| Verdict | Count |
|---|---|
| **Keep as JSONB** | 38 |
| **Promote to typed** | 16 |

---

## Promote (16)

Grouped by the migration each needs, because the shape of the fix — not the
table it lives in — is what makes these separable pieces of work.

### A. Scalar arrays → `ARRAY(TEXT)` (6)

Lists of plain strings. JSONB buys nothing here and costs indexability: you
cannot put a GIN index on `?| ARRAY['x']` semantics as cheaply as on a real
text array, and the ORM surfaces them as untyped `list`.

| Column | Annotation | Rationale |
|---|---|---|
| `users.password_history` | `Mapped[List[str]]` | List of prior bcrypt hashes, newest first, capped at `PASSWORD_HISTORY_LIMIT`. Homogeneous strings; `backend/api/auth.py:158-162` slices it like a list. |
| `users.mfa_recovery_codes` | `Mapped[list]` | `AuthService._generate_recovery_codes` is documented as returning "(plaintext, bcrypt-hashed) lists of 10 one-time recovery codes" — a flat list of hash strings. |
| `skills.required_tools` | `Mapped[List[str]]` | MCP tool names. Promoting enables the query the current shape forbids: "which skills require `splunk.search`?" |
| `custom_agents.recommended_tools` | `Mapped[list]` | Same content as above, same argument. |
| `workflow_runs.skill_tools_available` | `Mapped[list]` | Written from `skill_tool_names` (`services/workflows_service.py:740`) — a name list. |
| `custom_workflows.trigger_examples` | `Mapped[list]` | Example trigger phrases. **Shape inferred from name and `or []` handling, not confirmed from a writer that constructs the elements** — confirm before migrating. |

### B. One-to-many relations → child tables (7)

These are collections of records with their own identity, ordering and
timestamps, stored as a JSON array on the parent. That costs three things:
rows cannot be indexed, filtered or paginated; a concurrent append is a
read-modify-write of the whole array and can silently lose the other writer's
entry; and there is no FK to attribute an entry to a user or finding.

| Column | Annotation | Rationale |
|---|---|---|
| `case_evidence.chain_of_custody` | `Mapped[List[dict]]` | **Highest priority.** An evidence chain of custody is an append-only legal record. In JSONB it cannot be constrained append-only, cannot be indexed by actor or time, and every append rewrites the array — so two concurrent custody events can drop one. |
| `findings.mitre_predictions` | `Mapped[dict]` | `{technique_id: confidence}` — a typed map read by `services/graph_builder_service.py:334`. A child table `(finding_id, technique_id, confidence)` enables "findings by technique", which is core SOC triage and currently impossible without a full scan. Highest query value of the set. |
| `cases.timeline` | `Mapped[List[dict]]` | Append-only case events, rendered chronologically. Same concurrency and indexing argument. |
| `cases.notes` | `Mapped[List[dict]]` | Analyst notes — want author FK, edit timestamps, and pagination. |
| `cases.activities` | `Mapped[Optional[List[dict]]]` | Same family as `timeline`; worth deciding whether these two are one table with a discriminator rather than two. |
| `cases.resolution_steps` | `Mapped[Optional[List[dict]]]` | Ordered steps with completion state — ordering and state belong in columns. |
| `case_tasks.checklist_items` | `Mapped[Optional[List[dict]]]` | Individually checkable items; each needs its own state and ideally its own FK. |

### C. RBAC → `role_permissions` join table (1)

| Column | Annotation | Rationale |
|---|---|---|
| `roles.permissions` | `Mapped[dict]` | A flat `permission-name → bool` map (`database/init/06_auth_tables.sql:59+`). **The promotion is semantically lossless:** `AuthService.check_permission` is `role.permissions.get(permission, False)`, so an absent key already means denied and the stored explicit `false` entries are documentary only. Promoting makes "which roles can approve AI decisions?" a query instead of a scan. **Security-critical — see the caveat below.** |

### D. Small flag sets → real columns (1)

| Column | Annotation | Rationale |
|---|---|---|
| `case_watchers.notification_preferences` | `Mapped[Optional[dict]]` | A handful of notification booleans. Small, low-risk, and typed columns document the available switches that JSONB hides. |

### E. Promote pending shape confirmation (1)

| Column | Annotation | Rationale |
|---|---|---|
| `investigations.trigger_ids` | `Mapped[List[dict]]` | The annotation says `List[dict]` but the name and use (`daemon/orchestrator.py:950`, `inv.trigger_ids or []`) suggest a list of finding-id strings. **Annotation and name disagree — resolve which is true before choosing `ARRAY(TEXT)` versus a join table.** That disagreement is itself a finding: the ORM type is not trustworthy here. |

---

## Keep as JSONB (38)

Grouped by *why*, since "it's a dict" is not a reason.

### Arbitrary third-party payloads (8)
Shape is owned by an external vendor or tool and changes without our involvement.

`threat_indicators.raw_stix` (raw STIX from the feed) · `case_iocs.enrichment_data`
(VirusTotal / Shodan / OTX all differ) · `case_attachments.scan_details` (AV
scanner output) · `case_evidence.analysis_results` (output of whichever forensic
or malware-analysis tool ran — one shape per tool) · `attack_layers.layer_data`
(MITRE Navigator layer — an external interchange format) ·
`llm_interaction_logs.request_messages` · `llm_interaction_logs.tool_calls` ·
`llm_interaction_logs.tool_results` (provider message wire formats).

### Per-instance configuration, polymorphic by design (8)
The whole point is that each row's shape differs.

`system_config.value` · `user_preferences.preferences` · `integration_configs.config`
· `llm_provider_configs.config` · `ai_model_configs.settings` ·
`federation_sources.cursor` (the column comment already says "adapter-defined") ·
`config_audit_log.old_value` · `config_audit_log.new_value` (snapshots of the
above — necessarily as loose as what they snapshot).

### Model output (2)
`findings.ai_enrichment` — the LLM enrichment record. Its keys track the prompt's
requested schema and it deliberately carries `raw_response`; pinning it to columns
would make every prompt change a migration. `ai_decision_logs.decision_metadata` —
open-ended by name and contract.

### Heterogeneous by source (2)
`findings.entity_context` — genuinely irregular: sources disagree on singular vs
plural (`src_ip` vs `src_ips`), on `dst` vs `dest`, and integrations graft
sub-objects in (`entity_context["vstrike"]`). `findings.evidence_links` — small,
display-only link list; promoting adds a table without enabling a query anyone
makes.

### Documents versioned as a unit (7)
Authored artefacts where the array *is* the thing, edited and saved whole.

`skills.input_schema` and `skills.output_schema` (literally JSON Schema documents
— promoting a schema to columns is a category error) · `skills.execution_steps`
(the interpreted skill program) · `custom_workflows.phases` (workflow definition)
· `case_templates.task_templates` · `case_templates.playbook_steps` (template
bodies) · `sla_policies.escalation_rules` (rule DSL).

### Per-invocation context and results (9)
Contents depend entirely on which trigger fired or which action ran.

`workflow_runs.trigger_context` · `workflow_run_phases.input_context` ·
`workflow_run_phases.output` · `approval_actions.parameters` ·
`approval_actions.evidence` · `approval_actions.execution_result` ·
`investigations.proposed_actions` · `investigation_logs.details` ·
`case_notifications.notification_metadata`.

### UI state (1)
`custom_workflows.graph_layout` — canvas coordinates. No query will ever filter on
it.

### Provider-shaped conversation data (1)
`chat_messages.tool_calls` — same wire format argument as the interaction logs.

---

## Cross-cutting findings

These came out of the audit and matter more than several individual verdicts.

**1. The ORM and the init SQL disagree about the schema.** The ORM declares 54
JSONB columns across 32 classes; `database/init/*.sql` declares 27 across 16
tables. The gap exists because `create_all` still builds tables absent from the
init SQL — exactly what #411 (adopt Alembic, retire `create_all`) sets out to
end. Any promotion must decide which artefact it is changing, and a promotion
touching a table that exists in *both* has to change both consistently.

**2. Promotions that touch `database/init/` inherit the Helm checklist.** Per
`CLAUDE.md`, the chart bundles a *copy* under `helm/vigil/files/database-init/`.
A new or modified init file must be copied there, added to
`helm/vigil/values.yaml` `dbInit.sqlFiles` **in execution order**, and verified
with `helm template ... | grep -E '^[[:space:]]*apply "NEWFILE\.sql"'`. Skipping
the copy while keeping the filename in `dbInit.sqlFiles` hard-fails the dbInit
Job at runtime. This belongs in every follow-up issue, not just this document.

**3. `roles.permissions` is security-critical.** `get_user_permissions` returns
`Dict[str, bool]` and the SPA gates UI on it, so the API must keep serving that
shape even after the storage becomes a join table — derivable, but it means the
migration is not purely internal. Migrate this one on its own, behind tests that
assert the same allow/deny outcome for every seeded role before and after.

**4. `investigations.trigger_ids` has an untrustworthy ORM type.** Annotated
`List[dict]`, used as if it were a list of ids. Worth a grep of the writers
before anyone relies on either reading.

---

## Proposed follow-up issues

One issue per PR, grouped so each is independently reviewable and revertible.

**On the #411 dependency.** These need a migration mechanism, but "blocked on
#411" overstates it, and the difference is per-deploy-path:

- **Helm:** already has forward migration. `helm/vigil/templates/db-init-job.yaml`
  maintains `_vigil_schema_versions(filename PRIMARY KEY, applied_at)` and skips
  files already recorded, so a new numbered file in `database/init/` *does* apply
  on `helm upgrade`.
- **docker-compose:** has none. `database/init/` is mounted at
  `/docker-entrypoint-initdb.d`, which Postgres runs **only when initialising an
  empty data directory** — so an existing local database never sees a new file.
  A developer has to recreate the volume or apply the SQL by hand.

So each promotion below is *deliverable* today via a numbered init file, at the
cost of a manual step for existing compose databases. #411 is what makes the
mechanism uniform and reversible, not what makes these possible. Each follow-up
should state which path it has verified.

| # | Scope | Columns | Why separate |
|---|---|---|---|
| 1 | Security scalar arrays → `ARRAY(TEXT)` | `users.password_history`, `users.mfa_recovery_codes` | Touches credential material; wants its own review and its own tests |
| 2 | Tool-name arrays → `ARRAY(TEXT)` | `skills.required_tools`, `custom_agents.recommended_tools`, `workflow_runs.skill_tools_available`, `custom_workflows.trigger_examples` | Mechanical and low-risk; one migration. Confirm `trigger_examples`' element type first |
| 3 | `case_evidence.chain_of_custody` → child table | 1 | Correctness, not tidiness: append-only legal record currently open to lost updates |
| 4 | `findings.mitre_predictions` → child table | 1 | Highest query value; touches the hottest table, so it deserves isolation |
| 5 | Case children → child tables | `cases.resolution_steps`, `case_tasks.checklist_items` | The `timeline` / `activities` / `notes` trio was split out and filed separately — see below |
| 6 | `roles.permissions` → `role_permissions` | 1 | Security-critical; must preserve the `Dict[str, bool]` API shape |
| 7 | `case_watchers.notification_preferences` → columns | 1 | Small and self-contained; a good first migration once #411 lands |
| 8 | Resolve `investigations.trigger_ids`' real shape | 1 | Investigation, not migration — decides whether it lands in issue 2 or 5 |

### Already filed: the `cases` event trio

`cases.timeline`, `cases.activities` and `cases.notes` turned out to be the same
concept stored three ways — `backend/api/timeline.py:95-119` already flattens all
three into one stream and gives `timeline` and `activities` the **same**
`type="activity"`. `activities` is a strict superset of `timeline`
(`{timestamp, activity_type, description, details}` vs `{timestamp, event}`), so
unification means adopting that shape, not reconciling peers.

Filed as three sequenced issues, one PR each, in this order:

| Order | Issue | Scope | Blocked by |
|---|---|---|---|
| 1 | [#543](https://github.com/Vigil-SOC/vigil/issues/543) | Fix silent loss of in-place JSONB appends — a **live bug**, not a refactor | nothing |
| 2 | [#544](https://github.com/Vigil-SOC/vigil/issues/544) | Unify the three into `case_events`, API output unchanged | #543 |
| 3 | [#545](https://github.com/Vigil-SOC/vigil/issues/545) | Collapse the API to one stream, drop the legacy columns | #544 |

#543 must land first: it fixes `case.timeline.append(...)` silently failing at
`services/case_workflow_service.py:403` (auto-assignment) and `:470`
(escalation) — no JSONB column is wrapped in `MutableList` and `flag_modified`
appears nowhere in the codebase, so SQLAlchemy emits no `UPDATE`. Migrating
before that fix would backfill from columns already missing events. It is worth
landing on its own merits even if #544 and #545 are never approved.

---

*Analysis by Claude (Claude Code), reviewed by @craig-dt before publishing.
Verified against `main` at `311790e`.*
