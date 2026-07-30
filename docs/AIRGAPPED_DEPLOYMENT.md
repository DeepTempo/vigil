# Airgapped Deployment Guide

Deploying Vigil into networks with no route to the public internet.

**Audience:** the platform engineer who will install and operate Vigil inside a
restricted network. Assumes working knowledge of Docker or Kubernetes; assumes
no prior knowledge of Vigil.

**Out of scope (this revision):** hardware sizing and capacity planning. Where a
decision depends on hardware — notably GPU selection for local inference — this
guide states the dependency and stops.

---

## Table of Contents

- [1. Read this first](#1-read-this-first)
- [2. Deployment tiers](#2-deployment-tiers)
- [3. The inference decision](#3-the-inference-decision)
- [4. Integration inventory: what survives](#4-integration-inventory-what-survives)
- [5. Software bill of materials](#5-software-bill-of-materials)
- [6. Getting artifacts across the boundary](#6-getting-artifacts-across-the-boundary)
- [7. Install: Docker Compose](#7-install-docker-compose)
- [8. Install: Helm / Kubernetes](#8-install-helm--kubernetes)
- [9. Offline configuration and known gotchas](#9-offline-configuration-and-known-gotchas)
- [10. Restricted egress: firewall and ACL reference](#10-restricted-egress-firewall-and-acl-reference)
- [11. Staying current](#11-staying-current)
- [12. Acceptance checklist](#12-acceptance-checklist)
- [13. Known limitations](#13-known-limitations)

---

## 1. Read this first

Three things determine whether an airgapped Vigil deployment succeeds. Read all
three before planning the install.

### 1.1 Vigil does not phone home

There is no licensing callback, no usage telemetry, no update check, and no
analytics SDK in the product. The frontend ships no Sentry/PostHog/Segment/
Datadog client. Observability (OpenTelemetry, Jaeger, Prometheus, Grafana) is
self-hosted and stays inside your network.

Every outbound connection Vigil makes is one **you** configured: an LLM
provider, or an integration you enabled. Disable the integration and the traffic
stops. This is the answer to the first question most security reviewers ask.

### 1.2 The LLM is the airgap problem

Vigil's 13 agents are LLM-driven. Triage, investigation, threat hunting,
correlation, and reporting are all model inference. In an airgapped network
`api.anthropic.com` is unreachable, so **you must supply inference locally**.

This is a capability decision, not a packaging one, and it is the single largest
factor in how good the deployed system feels. See [section 3](#3-the-inference-decision).

### 1.3 Most of the integration catalog does not survive an airgap

Vigil ships 40 MCP integrations. Many of them *are* internet services —
VirusTotal, Shodan, and ANY.RUN have no on-premise edition, so no amount of
mirroring or vendoring brings them inside. Roughly a quarter of the catalog is
viable in a fully airgapped network.

That is not a defect; it is what "airgapped threat intelligence" means. But it
must be understood during procurement, not discovered during acceptance testing.
See [section 4](#4-integration-inventory-what-survives).

---

## 2. Deployment tiers

"Airgapped" means different things to different security programs. Vigil
supports three postures. Identify yours before reading further — several later
sections branch on it.

| Tier | Description | Artifact transfer | Integrations |
|------|-------------|-------------------|--------------|
| **Tier 1 — Fully airgapped** | No route to the internet, ever. Typical of classified networks and SCIFs. | Removable media only ("sneakernet") | On-prem only |
| **Tier 2 — Dark site with mirror** | No direct internet, but an internal registry (Harbor / Nexus / Artifactory) is populated from a staging host. Most common enterprise reading of "airgapped". | Internal registry | On-prem only |
| **Tier 3 — Restricted egress** | Outbound allowed to an explicit allowlist through a proxy or firewall. Not truly airgapped. | Direct pull, allowlisted | Allowlisted SaaS may work |

**Tiers 1 and 2 differ only in how artifacts arrive.** The installed system is
identical, and sections 3, 4, 5, and 9 apply to both. Section 6 covers the
transfer mechanism for each.

**Tier 3 is a different exercise** — it is an allowlisting problem, not a
packaging problem. If this is you, read [section 10](#10-restricted-egress-firewall-and-acl-reference)
and skip sections 5 and 6.

---

## 3. The inference decision

Every agent invocation is a model call. With no internet, inference must run on
hardware you control. Vigil routes **all** LLM traffic through **Bifrost**, an
LLM gateway that runs as a container in the stack, so the rest of the platform
is indifferent to which engine sits behind it.

That indirection is what makes airgapped operation tractable: point Bifrost at a
local engine and the agents, workflows, and daemon are unchanged.

### 3.1 Options

| Option | Best for | Trade-off |
|--------|----------|-----------|
| **Ollama** (recommended for most sites) | Single-site deployments, pilots, up to a handful of concurrent analysts | Simplest operationally. Vigil already has first-class support: `services/ollama_process.py` manages the process, `services/local_ai_recovery.py` handles restarts, and it can be autostarted from Settings → Services. Throughput is modest. |
| **vLLM or TGI** | Real production volume, multi-analyst SOCs, existing GPU infrastructure | Much better throughput and batching. Exposed to Bifrost over its OpenAI-compatible endpoint. More operational surface: you own the serving stack. |
| **Customer-supplied endpoint** | Organizations with an existing internal LLM platform | Vigil needs only an OpenAI-compatible URL. Cleanest boundary; quality and availability become the platform team's responsibility. |

**Recommendation:** start with **Ollama** for pilots and single-site
installations. Move to **vLLM** when concurrent analyst load or investigation
latency justifies owning a serving stack. If the organization already runs an
internal inference platform, use it — the integration is a URL.

> **Needs an engineer's sign-off.** Choosing between Ollama and vLLM, sizing
> the model, and matching GPUs to expected investigation volume is capacity
> planning work. This guide deliberately does not estimate it. Bring in
> whoever owns the GPU budget before committing.

### 3.2 Be honest about quality

A locally-hosted open-weight model is **not** equivalent to a frontier model.
Expect measurably weaker triage reasoning, weaker multi-step tool use, and more
frequent malformed tool calls. Agents that chain many tool calls — Investigator,
Threat Hunter, Forensics — degrade the most, because error compounds across
steps.

This is a real and permanent trade-off of airgapped operation. Set the
expectation during procurement.

### 3.3 Choose a tool-capable model

Vigil's agents are **tool-heavy** — an investigation is mostly tool calls, not
prose. A model that cannot reliably emit structured tool calls will appear to
run (clean iterations, no errors) while accomplishing nothing.

When selecting a local model:

- Verify tool/function-calling support explicitly. Do not assume it from the
  model family — support varies by *variant and version*, not just by name.
- Prefer larger instruction-tuned variants; tool-calling reliability degrades
  sharply at small parameter counts.
- Validate with a real investigation, not a chat prompt. A model can hold a
  conversation and still never emit a tool call.

Vigil registers Ollama with a wildcard model allow-list (`"models": ["*"]` in
`docker/bifrost/config.json`), so any model you pull or build locally routes
without further configuration — including custom in-house models.

---

## 4. Integration inventory: what survives

Vigil ships 40 MCP integrations. For airgap planning they fall into three
groups. **Verify this table against your enabled set** — the constraint is
whether the *target service* is reachable, not whether Vigil supports it.

### 4.1 Viable in a fully airgapped network

These reach services you can host inside the boundary.

| Integration | Notes |
|-------------|-------|
| `deeptempo-findings`, `tempo-flow`, `attack-layer`, `approval`, `mempalace` | Vigil-internal. Ship in-repo, need no credentials, no external target. On by default. |
| `splunk-selfhosted` | On-prem Splunk. Use this, **not** the `splunk` entry — see 4.2. |
| `elastic` | Self-hosted Elasticsearch. |
| `misp` | Self-hosted MISP. **Your airgapped threat-intel substrate** — see 4.4. |
| `cape-sandbox` | Self-hosted CAPE. **Your airgapped detonation capability** — see 4.4. |
| `palo-alto`, `carbon-black` | Viable *if* deployed with an on-premise management plane. Cloud-managed tenants are not. |

### 4.2 Ship in-repo but call an internet service

The code is local; the target is not. These will fail in Tiers 1 and 2, and
require explicit allowlisting in Tier 3.

`alienvault-otx`, `slack`, `microsoft-defender`, `microsoft-teams`, `azure-ad`,
`hybrid-analysis`, `anyrun`, `ip-geolocation`, `url-analysis`, `cloudflare`,
`vstrike`

### 4.3 Fetch their own code at every startup

**This is the airgap trap.** 18 of the 40 integrations do not ship in the repo —
they are downloaded at *process launch* via `npx -y`, `uvx`, `uv`, or
`docker run`. Two fetch directly from GitHub at runtime
(`sentinelone`, `cribl-stream`).

`github`, `security-detections`, `loglm`, `crowdstrike`, `sentinelone`,
`azure-sentinel`, `splunk` (the `mcp-remote` variant), `pagerduty`, `okta`,
`jira`, `joe-sandbox`, `virustotal`, `shodan`, `gcp-secops`, `gcp-threat-intel`,
`gcp-scc`, `aws-security`, `cribl-stream`

Why this matters: these fail at **agent-invocation time**, not at deploy time. A
naive airgapped install passes every startup health check and looks healthy for
days — until an analyst asks for a CrowdStrike lookup and the agent stalls
fetching `falcon-mcp` from PyPI.

Two of these are worth vendoring even in a full airgap because their *targets*
can be internal:

- **`security-detections`** — detection content, useful offline.
- **`loglm`** and **`splunk`** — point at `${LOGLM_MCP_URL}` / `${SPLUNK_MCP_URL}`,
  which can be internal hosts. But `mcp-remote` itself is fetched from npm.

Vendoring means pre-installing the package into the backend/daemon images (or an
internal npm/PyPI mirror) so the launcher resolves locally. **Disable every
integration you do not vendor** — see [section 9.5](#95-disable-what-you-cannot-reach).

### 4.4 Substitutions for lost capability

| Lost | Replace with |
|------|--------------|
| VirusTotal, AlienVault OTX, GTI (intel lookup) | **MISP**, populated by periodic offline feed import |
| ANY.RUN, Joe Sandbox, Hybrid Analysis (detonation) | **CAPE Sandbox**, self-hosted |
| Shodan (external exposure) | No substitute. External attack-surface data is inherently an internet service. |
| PagerDuty, Slack, Jira (notify/ticket) | On-prem equivalents via internal endpoints, or Vigil's own case management |

---

## 5. Software bill of materials

Everything that must cross the boundary. Applies to Tiers 1 and 2.

### 5.1 Container images

**Required — the platform will not run without these:**

| Image | Role |
|-------|------|
| `ghcr.io/vigil-soc/vigil-backend` | FastAPI API + the built frontend (see 5.4) |
| `ghcr.io/vigil-soc/vigil-daemon` | Autonomous SOC daemon |
| `pgvector/pgvector:pg16` | PostgreSQL 16 + pgvector |
| `redis:7-alpine` | ARQ job queue |
| `maximhq/bifrost` | LLM gateway — **all** inference routes through it |

**Optional — omit to shrink the bundle:**

`dpage/pgadmin4`, `otel/opentelemetry-collector-contrib:0.100.0`,
`jaegertracing/all-in-one:1.57`, `prom/prometheus:v2.51.2`,
`grafana/grafana:10.4.0`, `splunk/splunk`, `apache/kafka:3.7.0`,
`curlimages/curl:8.10.1` (Helm chart helper)

> **Pin by digest before mirroring.** `maximhq/bifrost`, `dpage/pgadmin4`, and
> `splunk/splunk` are referenced as `:latest` in `docker/docker-compose.yml`.
> A floating tag is unreproducible and unauditable — resolve each to a
> `sha256:` digest at bundle time and record it in the transfer manifest.
> Airgapped sites are usually the ones that most need a fixed, attestable BOM.

**If you build images inside the boundary** rather than transferring them, you
also need the build bases: `node:20-slim` and `python:3.11-slim`.

### 5.2 Python dependencies

- 57 direct requirements in `requirements.txt` (transitive closure is larger).
- Three **git submodules installed as editable packages** — easy to miss:
  `deeptempo-core`, `mcp-servers`, `mempalace`. Clone with
  `--recurse-submodules`; a bundle built from a shallow clone silently omits
  them and the backend fails at import.

If you transfer images rather than source, Python deps are already baked in and
you can skip this.

### 5.3 Node dependencies

Needed **only at image build time**. See 5.4.

### 5.4 The frontend needs no runtime Node

`docker/Dockerfile.backend` builds the React SPA in a `node:20-slim` stage and
copies the static output into the runtime image, where FastAPI serves it via
`StaticFiles`.

Practical consequence: **if you transfer built images, you need no npm registry
access inside the boundary at all.** This removes what is usually the single
most painful airgap dependency. Prefer transferring images over building
in-place.

### 5.5 Model weights

Usually the largest artifact in the bundle — often larger than every container
image combined. Plan removable media capacity accordingly and transfer weights
as a separate, resumable payload.

### 5.6 Vendored MCP packages

The npm and PyPI packages behind the 18 runtime-fetched integrations in
[4.3](#43-fetch-their-own-code-at-every-startup), for whichever subset you have
decided to keep.

---

## 6. Getting artifacts across the boundary

### 6.1 Tier 2 — internal mirror (recommended)

The lower-friction path, and the one most enterprises already have
infrastructure for.

1. On an internet-connected staging host, pull every image from
   [5.1](#51-container-images) and resolve each to a digest.
2. Re-tag into your internal registry and push
   (`harbor.internal/vigil/vigil-backend:0.4.0`, …).
3. Populate internal PyPI and npm mirrors (Nexus/Artifactory) with the vendored
   MCP packages from [5.6](#56-vendored-mcp-packages).
4. Point the deployment at the internal registry — a values override in Helm
   (see [8.2](#82-retarget-the-registry)) or image overrides in Compose.

### 6.2 Tier 1 — sneakernet bundle

1. On the staging host, `docker save` each image to a tarball.
2. Add model weights, the Helm chart or compose files, and the vendored MCP
   packages.
3. Produce a manifest listing every artifact with its `sha256`, plus the
   resolved image digests from [5.1](#51-container-images).
4. Sign the manifest. Transfer on approved media.
5. Inside the boundary, verify signature and checksums, then `docker load` each
   image.

> **Tooling gap — be aware.** Vigil does **not** currently ship a bundle-builder
> script. There is no `scripts/build-airgap-bundle.sh`. The steps above are
> performed manually today. Automating this is a recommended follow-on; until
> then, budget engineering time for it and keep the manifest under version
> control so successive transfers are diffable.

---

## 7. Install: Docker Compose

Best for single-site installs and Tier 1 networks where Kubernetes would add
operational burden without benefit.

1. **Load images** (Tier 1) or ensure the internal registry is reachable
   (Tier 2).
2. **Override image references** in `docker/docker-compose.yml` to your internal
   registry or loaded local tags.
3. **Trim the stack.** Remove optional services from
   [5.1](#51-container-images) you did not transfer. Keep postgres, redis,
   bifrost, backend, daemon.
4. **Configure `.env`** from `env.example` — bootstrap settings only (database
   URL, ports, `BIFROST_URL`, `OLLAMA_URL`). Provider keys and integration
   credentials are **not** set here; they are configured in the UI and stored
   encrypted. See [9.4](#94-secrets-stay-local).
5. **Start infrastructure first:** `docker compose up -d postgres redis`. The
   schema initializes from `database/init/`, applied in **lexicographic filename
   order**.
6. **Start Bifrost**, then verify it can reach your inference engine before
   starting anything else. Most failed airgapped installs fail here — see
   [9.1](#91-bifrost-blocks-private-network-targets-by-default).
7. **Start backend and daemon.**

---

## 8. Install: Helm / Kubernetes

Best for multi-node deployments and sites with existing Kubernetes operations.

### 8.1 Chart source

The chart lives at `helm/vigil/`. Transfer it as part of the bundle (Tier 1) or
publish it to an internal chart repository (Tier 2).

### 8.2 Retarget the registry

The chart is built for this. Image references derive from global values:

```yaml
global:
  imageRegistry: harbor.internal          # your internal registry
  imageNamespace: vigil-soc/vigil         # backend/daemon derive from this
  imagePullSecrets:
    - name: harbor-pull-secret
```

Backend and daemon repositories are left empty in `values.yaml` and auto-derive
from `imageNamespace` (`…-backend`, `…-daemon`), so retargeting the whole stack
is a single override. Dependency images (`pgvector/pgvector`, `redis`,
`curlimages/curl`, …) have their own `repository`/`tag` keys — override each to
its mirrored path.

### 8.3 Database initialization — read this before adding SQL

The chart does **not** apply `database/init/` directly. Helm can only read files
inside the chart directory, so the chart bundles a *copy* under
`helm/vigil/files/database-init/`, and the init Job applies files in the order
listed in `values.yaml` under `dbInit.sqlFiles` — **not** lexicographic order.

For a stock airgapped install this is transparent. It matters if you add
site-specific SQL: the file must be copied into the chart bundle *and* added to
`dbInit.sqlFiles`, or it will sit in the ConfigMap and never execute. See
`database/init/README.md`.

### 8.4 Inference engine placement

Bifrost must reach your inference engine. In-cluster (vLLM as a Deployment with
a Service) is usually cleanest — a cluster-internal Service address avoids the
private-network issue in [9.1](#91-bifrost-blocks-private-network-targets-by-default)
being a cross-host concern, though the Bifrost setting is still required for
RFC1918 targets.

---

## 9. Offline configuration and known gotchas

These are the failure modes specific to running Vigil with no internet. Each has
been hit in practice.

### 9.1 Bifrost blocks private-network targets by default

**Symptom:** every inference call fails with
`connection to private IP … is not allowed`.

Current Bifrost releases refuse to connect to RFC1918 addresses (10.x,
172.16–31.x, 192.168.x) unless explicitly permitted. In an airgapped network
your inference engine is *almost certainly* on an RFC1918 address, so this
setting is effectively **mandatory**:

```json
"ollama": {
  "network_config": {
    "allow_private_network": true
  }
}
```

It belongs in the provider's `network_config`. **Bifrost silently drops the
key-level form** — a misplacement produces no error, just continued failures.
Loopback (`127.0.0.1`, `::1`) is always permitted regardless.

Vigil ships this correctly configured for Ollama in `docker/bifrost/config.json`.
Replicate it for any provider block you add.

### 9.2 Editing Bifrost config requires a container recreate

Bifrost seeds its SQLite store (`/app/data/config.db`) from `config.json` **only
on first boot**. The store lives in the container's writable layer, so:

```bash
docker compose restart bifrost              # ← keeps the STALE config
docker compose up -d --force-recreate bifrost   # ← correct
```

This one costs people hours. Symptom: you fixed the config, and nothing changed.

### 9.3 Disable the model catalog refresh loop

The backend periodically syncs provider model catalogs from upstream
(`MODEL_CATALOG_REFRESH_INTERVAL_S`, default 300s). In an airgapped network any
Anthropic or OpenAI provider row makes this loop fail every five minutes
forever, filling logs with connection errors that mask real faults.

```bash
MODEL_CATALOG_REFRESH_INTERVAL_S=0   # sync once at startup, then stop
```

Also **delete unused provider rows** rather than leaving them configured. Local
Ollama is unaffected either way: Vigil forces a `["*"]` allow-list for Ollama
rather than relying on discovery, so a failed sync never breaks local routing.

### 9.4 Secrets stay local

Provider keys and integration credentials are configured in the UI (Settings →
AI / LLM Providers, Settings → Integrations) and stored encrypted at
`~/.vigil/secrets.enc` (`SECRETS_BACKEND=encrypted`). No external KMS or secret
manager is contacted. `.env` is for bootstrap settings only.

For Kubernetes, see `docs/HELM-SECRETS.md`.

### 9.5 Disable what you cannot reach

For every integration in [4.2](#42-ship-in-repo-but-call-an-internet-service)
and [4.3](#43-fetch-their-own-code-at-every-startup) that you are not keeping,
disable the MCP server rather than leaving it enabled-but-broken. Enabled-broken
integrations produce agent stalls and tool-call failures that are hard to
distinguish from model quality problems.

Disabling also **improves agent behavior**: fewer tools in context means better
tool selection, which matters more with a local model than with a frontier one.

### 9.6 Time synchronization

Airgapped networks need an internal NTP source. Token expiry, TLS validation,
and correlation windows all assume sane clocks — and the usual public NTP pools
are unreachable.

---

## 10. Restricted egress: firewall and ACL reference

> **⚠️ DRAFT — content pending review.** This section is scaffolded from a
> static inventory of hostnames found in the codebase and dependency manifests.
> It has **not** been validated against live traffic capture, and per-service
> port/protocol detail is still to be filled in. Treat it as a starting point
> for an allowlist, not an authoritative one. *(Flagged for discussion.)*

For **Tier 3** networks that permit outbound traffic to an explicit allowlist.

### 10.1 Principle

Vigil makes no outbound connection that you did not configure. The allowlist is
therefore a direct function of two choices: which LLM provider you use, and
which integrations you enable. Start from deny-all and open only what the
deployment actually needs.

### 10.2 Build and deploy time only

Needed to build images or populate mirrors. **Not** needed at runtime — these
can stay closed on the production network entirely.

| Host | Purpose |
|------|---------|
| `ghcr.io` | Vigil backend/daemon images |
| `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com` | Dependency images |
| `pypi.org`, `files.pythonhosted.org` | Python packages |
| `registry.npmjs.org` | Node packages (build stage only) |
| `github.com`, `codeload.github.com` | Submodules; two MCP servers fetched at runtime (see 4.3) |

### 10.3 LLM inference

Only if you are *not* running local inference. Choosing a hosted provider means
your security telemetry leaves the network — a decision that usually needs
separate authorization.

| Host | When |
|------|------|
| `api.anthropic.com` | Anthropic provider configured |
| `api.openai.com` | OpenAI provider configured |
| *(none)* | Local Ollama / vLLM — **the airgap-appropriate choice** |

### 10.4 Integrations

Open only the rows for integrations you enable.

| Integration | Host(s) |
|-------------|---------|
| CrowdStrike | `api.crowdstrike.com` |
| Microsoft Defender | `api.securitycenter.microsoft.com` |
| Microsoft Teams / Azure AD | `graph.microsoft.com`, `login.microsoftonline.com` |
| Azure Sentinel | `sentinelmcp.microsoft.com` |
| Slack | `slack.com` |
| Jira | `mcp.atlassian.com` |
| PagerDuty | `events.pagerduty.com` |
| VirusTotal | `www.virustotal.com` |
| Shodan | `api.shodan.io` |
| AlienVault OTX | `otx.alienvault.com` |
| Hybrid Analysis | `www.hybrid-analysis.com` |
| ANY.RUN | `api.any.run` |
| Joe Sandbox | `jbxcloud.joesecurity.org` |
| Cloudflare | `api.cloudflare.com` |
| IP geolocation | `ip-api.com` |
| vStrike | `vstrike.net` |
| GitHub | `github.com`, `api.github.com` |

### 10.5 Open questions for review

- Ports and protocols per row (assumed 443/TCP throughout — needs confirming).
- Whether to recommend a forward proxy with TLS inspection, and how Vigil should
  be configured to trust an internal CA.
- Whether egress should be enforced per-container (backend and daemon have
  materially different needs — the daemon runs autonomously and is the higher
  risk of the two).
- Validation method: static inventory versus live capture from a running
  deployment with all integrations enabled.

---

## 11. Staying current

Airgapped deployments trade freshness for isolation. Plan the cadence
explicitly — an unmaintained airgapped SOC degrades quietly.

| Artifact | Cadence | Mechanism |
|----------|---------|-----------|
| Vigil release | Per release | New bundle or mirror sync |
| Base image CVE patches | Monthly minimum | Rebuild + re-transfer |
| Threat intelligence | Weekly or faster | Offline feed import into MISP |
| Detection content | Per content release | `security-detections`, if vendored |
| MITRE ATT&CK mapping | No separate cadence | Code-resident (`services/mitre_lookup.py`); travels with the Vigil release. Technique names arrive primarily on the findings themselves, from whichever detection source produced them — so ATT&CK freshness follows your detection content, not a separate feed. |
| Model weights | Rarely | Only when changing models |

**Threat intel freshness is the one that hurts.** In a connected deployment,
VirusTotal and OTX are live. Airgapped, your intel is exactly as fresh as your
last MISP import. Make that import a scheduled operational duty with an owner,
not an ad-hoc task.

---

## 12. Acceptance checklist

Run inside the boundary, with the network genuinely disconnected, before
declaring the deployment complete.

**Platform**
- [ ] All required images present at pinned digests matching the transfer manifest
- [ ] Postgres reachable; schema applied; pgvector extension present
- [ ] Redis reachable; ARQ worker processing jobs
- [ ] Backend serves the UI (frontend assets present in the image)
- [ ] Daemon starts and stays up

**Inference — the critical path**
- [ ] Bifrost reaches the inference engine (no private-IP rejection — see 9.1)
- [ ] A chat prompt returns a real completion
- [ ] **An agent completes a tool-calling investigation end to end** — this is
      the test that distinguishes a working deployment from one that merely
      starts. Do not accept a chat reply as proof.
- [ ] Model catalog refresh disabled or provider rows cleaned up (9.3)

**Integrations**
- [ ] Every enabled integration reaches its target
- [ ] Every unreachable integration is **disabled**, not left failing (9.5)
- [ ] No integration attempts a `npx`/`uvx` fetch at invocation (4.3) — verify
      by invoking each, not by checking startup logs

**Isolation**
- [ ] Egress monitoring shows no unexpected outbound attempts under full load
- [ ] Internal NTP configured and clocks correct (9.6)

---

## 13. Known limitations

Honest constraints of an airgapped Vigil deployment.

1. **Reduced agent quality.** Local open-weight inference is measurably weaker
   than frontier models, most visibly on long tool-calling chains ([3.2](#32-be-honest-about-quality)).
2. **~75% of the integration catalog is unavailable** in a full airgap ([section 4](#4-integration-inventory-what-survives)).
3. **No live threat intelligence.** Intel is as fresh as the last offline import
   ([section 11](#11-staying-current)).
4. **No external attack-surface visibility.** Shodan-class capability has no
   on-premise substitute.
5. **No bundle-builder tooling yet.** Transfer packaging is manual
   ([6.2](#62-tier-1--sneakernet-bundle)).
6. **Floating image tags upstream.** Three dependency images ship as `:latest`
   and must be digest-pinned at bundle time ([5.1](#51-container-images)).

---

## Related documentation

| Document | Covers |
|----------|--------|
| [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) | Standard connected VM/Compose deployment |
| [HELM.md](HELM.md) | Helm chart reference |
| [HELM-SECRETS.md](HELM-SECRETS.md) | Secrets in Kubernetes |
| [CONFIGURATION.md](CONFIGURATION.md) | Environment variables |
| [INTEGRATIONS.md](INTEGRATIONS.md) | Integration and MCP reference |
| [PRODUCTION_SECURITY.md](PRODUCTION_SECURITY.md) | Production hardening |
| [STATE.md](STATE.md) | Secret and state storage |
| [docker/bifrost/README.md](../docker/bifrost/README.md) | Bifrost gateway configuration |
