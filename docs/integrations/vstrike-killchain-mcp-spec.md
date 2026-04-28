# VStrike kill-chain replay — integration ask

This document is the request to the CloudCurrent / VStrike engineering
team. Vigil's side is shipped; we want to drive a kill-chain animation
through the embedded VStrike iframe and need to know the shortest path
on your side. **The framing here is "here's our problem and what we
already have" — not a fixed design.** If your UI already does most of
this, the tool we end up calling can be much smaller than the strawman
below.

## The problem

When a Vigil analyst opens a case, every finding's
`entity_context.vstrike` carries an `attack_path` (an ordered list of
asset IDs from initial access to the target) and `adjacent_assets`
(MITRE technique on each edge). Vigil consolidates a case's findings
into a single deduplicated step list and wants to ask the embedded
VStrike iframe to **animate that list** — highlight each node in
order, draw the edge transitions, surface the technique label per
edge.

A "Play" button is already in Vigil's iframe toolbar. Until VStrike
exposes a way to drive replay, the button surfaces a friendly "VStrike
server doesn't yet implement kill-chain replay" notice and is otherwise
a no-op.

## What Vigil already has

The iframe embed and live tool calls (`ui-login-token`, `network-list`,
`ui-network-load`) are working end-to-end. For replay specifically,
Vigil produces a step list per case that looks like this:

```json
[
  { "node_id": "asset-001", "timestamp": "2026-04-28T11:00:00Z", "label": "Initial Access" },
  { "node_id": "asset-042", "timestamp": "2026-04-28T11:05:00Z", "technique": "T1021.002", "label": "Lateral movement → file-server" },
  { "node_id": "asset-077", "timestamp": "2026-04-28T11:12:00Z", "technique": "T1003.001", "label": "Target: domain-controller" }
]
```

The step list is sorted by timestamp, deduplicated by `node_id`,
length 1..N, and the same JWT-authenticated session is already open in
the iframe.

## Questions for you (in priority order)

1. **What replay capabilities does VStrike already have?**
   - Does the iframe app today support a "play this sequence" mode
     (timeline scrubber, animated path-walk, anything close)?
   - If yes: what's the shortest way for Vigil to trigger it? A new
     thin MCP tool that pushes our step list onto an existing
     animation engine? A URL/postMessage parameter? An existing tool
     we're not seeing in `tools/list`?
   - If no: see the strawman below for what we'd ask you to build.

2. **Edge animations between sequential nodes.** The kill-chain
   visualization the analyst wants is the *edges* drawing as
   transitions, not just the nodes blinking. Does the UI render edges
   as motion between sequential highlights today?

3. **`node_id` format.** Vigil emits the asset identifiers carried on
   case findings. We assume those match what `node-list` returns per
   network (`id` / `network_id` / `uuid`, in priority order). Please
   confirm or tell us what shape you actually want.

4. **Bidirectional "playback finished" signal.** Can the iframe emit a
   message back over its existing WebSocket when an animation ends, so
   Vigil's EventTimeline scrubber can sync? Nice-to-have. If absent,
   Vigil falls back to a `sum(dwell_ms)` estimate.

## Strawman tool — only if you're starting from zero

If there's no existing replay path on your side, here's a candidate
tool definition we can call. Names, fields, defaults are all
negotiable — happy to adopt whatever fits your existing patterns.

```jsonc
{
  "name": "ui-killchain-replay",
  "description": "Animate a kill-chain through the active VStrike UI session.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "networkId": {
        "type": "string",
        "description": "Network identifier. The tool should internally do a `ui-network-load` if the active session is on a different network."
      },
      "steps": {
        "type": "array",
        "minItems": 1,
        "items": {
          "type": "object",
          "properties": {
            "node_id":   { "type": "string" },
            "timestamp": { "type": "string",  "description": "ISO-8601." },
            "technique": { "type": "string",  "description": "Optional MITRE ATT&CK ID for the EDGE leading into this node (e.g. T1021.002)." },
            "label":     { "type": "string",  "description": "Optional human-readable annotation." },
            "dwell_ms":  { "type": "integer", "description": "Per-step dwell override; default 2000." }
          },
          "required": ["node_id", "timestamp"]
        }
      },
      "loop":      { "type": "boolean", "description": "Restart from step 0 after the last step (default false)." },
      "auto_play": { "type": "boolean", "description": "If false, load the steps but wait for the user (default true)." }
    },
    "required": ["networkId", "steps"]
  }
}
```

This borrows the contract of your existing `ui-network-load`:
WebSocket push to the active session, stateless server-side, JSON-RPC
`result.content[].text` confirmation with `isError` for failures.

## What a call would look like under the strawman

For shape only — Vigil already emits this exact payload via
`POST /api/integrations/vstrike/ui/killchain-replay`, which proxies to
your `/mcp` endpoint:

```bash
curl -X POST 'https://vstrike.example/mcp' \
  -H "Authorization: Bearer ${VSTRIKE_JWT}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{
    "jsonrpc": "2.0",
    "id": 1730000000000,
    "method": "tools/call",
    "params": {
      "name": "ui-killchain-replay",
      "arguments": {
        "networkId": "net-123",
        "steps": [
          { "node_id": "asset-001", "timestamp": "2026-04-28T11:00:00Z", "label": "Initial Access" },
          { "node_id": "asset-042", "timestamp": "2026-04-28T11:05:00Z", "technique": "T1021.002", "label": "Lateral movement → file-server" },
          { "node_id": "asset-077", "timestamp": "2026-04-28T11:12:00Z", "technique": "T1003.001", "label": "Target: domain-controller" }
        ],
        "loop": false,
        "auto_play": true
      }
    }
  }'
```

If your team renames the tool, restructures the schema, or replaces
the whole approach with something simpler that already exists — tell
us, and Vigil's adapter is a small edit.

## Contact

- Vigil repo: <https://github.com/Vigil-SOC/vigil>
- Vigil's outbound client (rename target if the tool name changes):
  [`services/vstrike_service.py`](../../services/vstrike_service.py) → `killchain_replay_in_ui`
- API surface: [`backend/api/vstrike.py`](../../backend/api/vstrike.py) → `POST /ui/killchain-replay`
- Frontend Play button: [`frontend/src/components/graph/VStrikeIframeHost.tsx`](../../frontend/src/components/graph/VStrikeIframeHost.tsx)
