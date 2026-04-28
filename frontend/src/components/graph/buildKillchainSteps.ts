import type { KillchainStep } from '../../contexts/VStrikeIframeContext'

export type { KillchainStep }

interface MaybeFinding {
  timestamp?: string | number | Date
  entity_context?: {
    vstrike?: {
      asset_id?: string
      attack_path?: string[]
      adjacent_assets?: Array<{
        asset_id?: string
        asset_name?: string
        edge_technique?: string
      }>
    }
  }
}

function toIso(ts: unknown): string {
  if (!ts) return new Date().toISOString()
  if (ts instanceof Date) return ts.toISOString()
  if (typeof ts === 'number') return new Date(ts).toISOString()
  if (typeof ts === 'string') {
    // Trust ISO-ish strings; otherwise let Date parse.
    const parsed = new Date(ts)
    if (!Number.isNaN(parsed.valueOf())) return parsed.toISOString()
    return ts
  }
  return new Date().toISOString()
}

function compareByTimestamp(a: MaybeFinding, b: MaybeFinding): number {
  const ta = a.timestamp ? new Date(a.timestamp).valueOf() : 0
  const tb = b.timestamp ? new Date(b.timestamp).valueOf() : 0
  return ta - tb
}

/**
 * Build a kill-chain step list from a case's findings.
 *
 * Walks findings in timestamp order, reads `entity_context.vstrike.attack_path`
 * and `adjacent_assets` from each, and emits one step per unique node_id (first
 * occurrence wins). Annotates each step with the MITRE technique from the
 * matching `adjacent_assets` entry (when available) and a human label that
 * varies for first/last/middle nodes.
 *
 * The output is consumed by VStrike's `ui-killchain-replay` MCP tool — the
 * shape matches that tool's input schema.
 */
export function buildKillchainSteps(
  findings: ReadonlyArray<MaybeFinding>,
): KillchainStep[] {
  const seen = new Map<string, KillchainStep>()
  const sorted = findings.slice().sort(compareByTimestamp)

  for (const f of sorted) {
    const v = f.entity_context?.vstrike
    if (!v?.attack_path?.length) continue

    const adjBy = new Map<string, { asset_name?: string; edge_technique?: string }>()
    for (const a of v.adjacent_assets ?? []) {
      if (a?.asset_id) {
        adjBy.set(a.asset_id, {
          asset_name: a.asset_name,
          edge_technique: a.edge_technique,
        })
      }
    }

    const path = v.attack_path
    path.forEach((node_id, i) => {
      if (!node_id || seen.has(node_id)) return
      const adj = adjBy.get(node_id)
      const label =
        i === 0
          ? 'Initial Access'
          : i === path.length - 1
            ? `Target: ${v.asset_id ?? node_id}`
            : `Lateral movement → ${adj?.asset_name ?? node_id}`
      seen.set(node_id, {
        node_id,
        timestamp: toIso(f.timestamp),
        ...(adj?.edge_technique ? { technique: adj.edge_technique } : {}),
        label,
      })
    })
  }

  return Array.from(seen.values())
}
