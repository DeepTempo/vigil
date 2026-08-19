# 14. The agent seam off-host: token and network policy, not loopback

Date: 2026-08-13

## Status

Accepted. **Amends ADR 0010** — keeps its guarantees, drops its loopback half.

Governs #635 (the agent image, the Helm deployment and the Node CI job).

## Context

ADR 0010 put every remote tool call through one authenticated Python endpoint,
`POST /internal/tools/invoke`, "loopback-bound **and** shared-secret
authenticated — either alone is a single point of failure." It named the
condition that would end that arrangement:

> The endpoint is high-value: it reaches every credential in the deployment.
> Loopback binding plus shared secret is the floor, not the ceiling, and it
> should be revisited if the agent service is ever deployed off-host.

#635 deploys it off-host. It makes **Agent Worker** and **Agent Serve**
independently scaling Deployments, at which point no traffic on the seam arrives
from loopback any more.

The seam is wider than the one endpoint 0010 describes. Eight routes cross it,
and the loopback predicate is written twice — `core/agents/internal_auth.py` and
`serve.ts` carry the same check under the same comment:

- Agent → Python: `/internal/tools/invoke`, `/internal/pricing`,
  `/internal/playbooks`, `/internal/runs` (progress, outcome, decisions)
- Python → Agent: `POST /chat/stream`, `GET /runs/<id>/projection`

Both directions currently 403 across a pod boundary, so the parked
`agent-worker` Deployment would start, dequeue a job and fail to resolve a
playbook before its first model call.

## Decision

Drop the loopback predicate on both sides. The bearer token becomes the sole
in-process check, and reachability is constrained by the chart's NetworkPolicy.

The loopback check existed because "a shared secret on a public bind is one leak
from open." NetworkPolicy answers that with a strictly stronger statement: it
names which pods may connect, where loopback only ever said "same box."

Every guarantee ADR 0010 asked for is unchanged — bounds enforcement,
read-only, row and time capping, deny-by-default allow-lists, refusal semantics.
This amends where the second factor is enforced, not what is enforced.

## Consequences

- **Compose is token-only.** There is no NetworkPolicy in docker-compose, so the
  second factor there is that `deeptempo-network` is a private bridge and the
  agent services publish no ports. Defensible, but it should be described
  accurately rather than as defence in depth.
- **Failing closed on an unset token becomes load-bearing.** Both sides already
  refuse when `AGENT_INTERNAL_TOKEN` is empty — Python 503s and says the secret
  is unconfigured, the agent 401s. That was belt-and-braces while loopback held;
  it is now the only thing between a reachable pod and an open endpoint.
- **The bind does not change, only the check.** `serve.ts` already listens on all
  interfaces; it was the check and not the socket that kept it closed.
- **The NetworkPolicy is less of a replacement than this decision first claimed,
  and the difference is worth stating plainly.** Two of the three edges are
  namespace-wide rather than pod-specific:
  - *Agent → Python `/internal/*`*: the chart's backend policy already admits
    any pod in the namespace on the backend port, because the daemon, llm-worker
    and the helm test all use it. Narrowing it is a change to those components,
    not to this seam, so it was left alone.
  - *Backend → agent-serve*: named to the backend pods — but health rides the
    traffic port, and NetworkPolicy ingress rules are OR'd, so the probe
    allowance re-opens it namespace-wide. `networkPolicies.agentServe.allowProbesFromAnyNamespace`
    exists to close that on a CNI known to permit node-sourced probes, and
    defaults to open because a blocked probe takes the Deployment down.

  So in-cluster the honest description is the same one compose gets: **the token
  is the gate, and the network is a coarse second layer.** That is still an
  improvement on a check that refused every legitimate caller, but it is not the
  pod-level containment "constrain reachability with NetworkPolicy" implies.
- ADR 0010's "floor, not the ceiling" still stands, and this decision does not
  raise the ceiling much. mTLS or a mesh is what would actually put a
  cryptographic identity on each end, and the consequence above is the argument
  for getting there.

## Alternatives considered

**Sidecar containers in the backend pod.** Preserves the property exactly, needs
no code change, and was the only genuine alternative. Rejected because Worker and
Serve would then scale with the API — independent scaling is the point of #635,
and a queue consumer and an SSE endpoint have nothing in common in how they load.

**A configurable check** (`AGENT_TRUST_NETWORK`, or a CIDR allow-list). Strict in
dev, relaxed in production. Rejected: a security check with a bypass flag is the
leak the original comment warned about, and the flag defaults wrong somewhere
eventually.

**mTLS or a service mesh.** The right end state and a larger lift than this
ticket, with a new cluster dependency.
