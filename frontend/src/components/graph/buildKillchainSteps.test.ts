import { describe, it, expect } from 'vitest'
import { buildKillchainSteps } from './buildKillchainSteps'

describe('buildKillchainSteps', () => {
  it('returns empty list when no findings carry vstrike enrichment', () => {
    expect(buildKillchainSteps([])).toEqual([])
    expect(
      buildKillchainSteps([
        { timestamp: '2026-04-28T11:00:00Z' },
        { timestamp: '2026-04-28T11:05:00Z', entity_context: {} },
      ]),
    ).toEqual([])
  })

  it('emits one step per attack-path node, deduped by node_id', () => {
    const findings = [
      {
        timestamp: '2026-04-28T11:05:00Z',
        entity_context: {
          vstrike: {
            asset_id: 'asset-077',
            attack_path: ['asset-001', 'asset-042', 'asset-077'],
            adjacent_assets: [
              {
                asset_id: 'asset-042',
                asset_name: 'file-server',
                edge_technique: 'T1021.002',
              },
              {
                asset_id: 'asset-077',
                asset_name: 'dc',
                edge_technique: 'T1003.001',
              },
            ],
          },
        },
      },
      {
        // Repeats one node — must not duplicate.
        timestamp: '2026-04-28T11:12:00Z',
        entity_context: {
          vstrike: {
            asset_id: 'asset-077',
            attack_path: ['asset-001', 'asset-077'],
            adjacent_assets: [],
          },
        },
      },
    ]

    const steps = buildKillchainSteps(findings)
    expect(steps.map((s) => s.node_id)).toEqual([
      'asset-001',
      'asset-042',
      'asset-077',
    ])

    expect(steps[0].label).toBe('Initial Access')
    expect(steps[0].technique).toBeUndefined()

    expect(steps[1].label).toBe('Lateral movement → file-server')
    expect(steps[1].technique).toBe('T1021.002')

    expect(steps[2].label).toBe('Target: asset-077')
    expect(steps[2].technique).toBe('T1003.001')
  })

  it('orders findings by timestamp (earliest first wins on dedupe)', () => {
    const findings = [
      {
        timestamp: '2026-04-28T11:30:00Z',
        entity_context: {
          vstrike: {
            asset_id: 'asset-002',
            attack_path: ['asset-002'],
            adjacent_assets: [],
          },
        },
      },
      {
        timestamp: '2026-04-28T11:00:00Z',
        entity_context: {
          vstrike: {
            asset_id: 'asset-001',
            attack_path: ['asset-001', 'asset-002'],
            adjacent_assets: [],
          },
        },
      },
    ]
    const steps = buildKillchainSteps(findings)
    expect(steps.map((s) => s.node_id)).toEqual(['asset-001', 'asset-002'])
    // asset-002 took its timestamp from the earlier-walking finding
    // (the second one in input order, which is first by timestamp).
    expect(steps[1].timestamp).toBe('2026-04-28T11:00:00.000Z')
  })

  it('serializes timestamps to ISO-8601 even when input is a Date', () => {
    const findings = [
      {
        timestamp: new Date(Date.UTC(2026, 3, 28, 11, 0)),
        entity_context: {
          vstrike: {
            asset_id: 'asset-1',
            attack_path: ['asset-1'],
            adjacent_assets: [],
          },
        },
      },
    ]
    const steps = buildKillchainSteps(findings)
    expect(steps).toHaveLength(1)
    expect(steps[0].timestamp).toMatch(/^2026-04-28T11:00:00\.000Z$/)
  })
})
