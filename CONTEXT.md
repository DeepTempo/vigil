# Vigil SOC

Vigil is an AI-native Security Operations Center: specialized AI agents perform
triage, investigation, threat hunting, and response across many security
integrations. This glossary fixes the language used across the codebase and
docs. It is a glossary, not a spec — it defines what terms *mean*, not how any
component is built.

## Language — package layout (Reorg R5)

**Domain**:
A named product capability slice whose service/daemon logic is being regrouped
under `core/<domain>/` as part of Reorg R5
([#486](https://github.com/Vigil-SOC/vigil/issues/486)). The R5 domain list is:
cases, workflows, threat_intel, reporting, response, detections, skills,
storage, auth, chat, ingestion, federation, platform.
_Avoid_: layer (that means backend/services/daemon), feature folder, module
bucket.

**Core domain package**:
The Python package at `core/<domain>/` that holds a domain's service and daemon
logic after a mechanical reorg. HTTP routers, schemas, SQL, and frontend stay
outside it.
_Avoid_: core module (ambiguous with flat `core/*.py` utilities), vertical
slice (broader than R5's services/daemon move).

**Import shim**:
A temporary module (or mirror package) left at a pre-reorg import path that
explicitly re-exports public names from the core domain package so existing
callers and tests keep working. Shims are removed in Reorg R8
([#489](https://github.com/Vigil-SOC/vigil/issues/489)).
_Avoid_: re-export facade (unless describing the pattern), compatibility
wrapper (too vague — shims must not change behavior).

**Mechanical reorg**:
A `git mv` of domain logic into a core domain package plus import shims, with
no intentional behavior change. One domain per pull request.
_Avoid_: refactor (implies logic change), cleanup (R8 removes shims; R5 only
moves).

**Chat (R5)**:
Conversation session, context, and tool-execution packaging around the product
chat experience (e.g. `services/chat/`). Distinct from LLM engines and the LLM
entry point, which belong to Reorg R4
([#485](https://github.com/Vigil-SOC/vigil/issues/485)).
_Avoid_: using "chat" for ClaudeService, LLMRouter, or provider plumbing.

## Flagged ambiguities

**"Core"** is overloaded: today it names both the flat shared utilities under
`core/*.py` (config, secrets, telemetry) and the destination for domain
packages (`core/<domain>/`). Prefer **core domain package** for the latter and
leave flat utilities unnamed as "platform" until the platform domain PR.

**"Platform"** in R5 is the last domain PR and may absorb or clarify those flat
`core/*.py` utilities; until then they stay put beside new domain packages.
