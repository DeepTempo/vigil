# R5 regroups domain logic under `core/<domain>/` behind temporary import shims

- **Status:** proposed
- **Date:** 2026-07-30
- **Issue:** [#486](https://github.com/Vigil-SOC/vigil/issues/486) (epic [#481](https://github.com/Vigil-SOC/vigil/issues/481))

## Context

Vigil's product logic is spread across layered directories (`services/`,
`daemon/`, `backend/api/`, …). Epic #481 regroups code toward
`core/<area>/` packages. Reorg R5 (#486) covers the remaining domains: cases,
workflows, threat_intel, reporting, response, detections, skills, storage,
auth, chat, ingestion, federation, and platform.

Call sites overwhelmingly use `from services.<module> import <Symbol>` (and
equivalent deep imports under packages like `daemon.federation.*` /
`services.chat.*`). Tests patch those same module paths. A naive move would
break imports; rewriting every caller in the same change would mix layout work
with large diffs and raise regression risk. R8 (#489) is already reserved to
remove temporary compatibility later.

## Decision

R5 is a **mechanical reorg**, delivered **one domain per pull request**:

1. **Move only service/daemon domain logic** into a **core domain package** at
   `core/<domain>/`. Leave `backend/api/`, schemas, SQL, frontend, and
   workflow markdown definitions in place.
2. After each `git mv`, leave an **import shim** at the old path that
   **explicitly re-exports** the public names callers and tests already use.
   Do not use `import *` shims.
3. For existing packages (`daemon/federation/`, `services/chat/`, …), move the
   whole tree and leave a **mirror shim package** so deep imports
   (`daemon.federation.runner`, `services.chat.context_manager`, …) keep
   working without rewriting callers in the R5 PR.
4. Code inside a core domain package imports siblings via
   `core.<domain>…`. External callers keep old paths until R8 removes shims.
5. Existing flat modules already under `core/*.py` (config, secrets,
   telemetry, …) stay put until the final **platform** domain PR.
6. **Chat** in R5 means conversation session/context/tool-execution packaging.
   LLM engines and the LLM entry point remain R4 (#485).

## Considered options

- **A — Move services/daemon only; explicit shims; one domain per PR (chosen).**
  Matches #486's "git mv + shims / no behavior change / one domain per PR"
  framing and preserves the dominant import and patch style in the repo.
- **B — Move API routers and schemas with each domain.** Rejected for R5:
  couples FastAPI wiring into every mechanical PR and is closer to a full
  vertical-slice migration than this issue's scope.
- **C — Rewrite all callers to `core.<domain>` in the same PR (no shims).**
  Rejected: large blast radius, harder review, and conflicts with the planned
  R8 shim-removal lane.
- **D — Star-import shims (`from core… import *`).** Rejected: the codebase
  never imports services that way; explicit re-exports make the public surface
  and R8 cleanup obvious.

## Consequences

- Each R5 PR is small and reviewable, but the tree carries temporary shim
  modules until R8.
- Shim authors must enumerate symbols that are imported or patched; missing a
  name fails imports/tests rather than failing silently.
- Early R5 PRs add packages beside flat `core/*.py`; the platform PR owns the
  harder question of whether those utilities nest under `core/platform/`.
- Chat and LLM owners must not cross-move each other's modules; coordinate if
  a file sits on the boundary.
- Acceptance for #486: domain logic under `core/<domain>/`, old imports resolve
  via shims, no intentional behavior change.
