import { describe, expect, it } from 'vitest'
import {
  DEFAULT_FINDINGS_VIEW_PREFERENCES,
  FINDINGS_VIEW_STORAGE_KEY,
  loadFindingsViewPreferences,
  saveFindingsViewPreferences,
} from './findingsPreferences'

function memoryStorage(initial?: string): Storage {
  const values = new Map<string, string>()
  if (initial !== undefined) values.set(FINDINGS_VIEW_STORAGE_KEY, initial)
  return {
    get length() { return values.size },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => { values.delete(key) },
    setItem: (key, value) => { values.set(key, value) },
  }
}

describe('findings view preferences', () => {
  it('falls back safely for corrupt or invalid stored values', () => {
    expect(loadFindingsViewPreferences(memoryStorage('{'))).toEqual(DEFAULT_FINDINGS_VIEW_PREFERENCES)
    expect(loadFindingsViewPreferences(memoryStorage(JSON.stringify({
      severity: 'urgent',
      source: '',
      hiddenColumns: ['host', 7, 'host', ''],
    })))).toEqual({ severity: 'any', source: 'any', hiddenColumns: ['host'] })
  })

  it('round-trips a bounded versioned preference record', () => {
    const storage = memoryStorage()
    const preferences = { severity: 'high' as const, source: 'splunk', hiddenColumns: ['host', 'user'] }
    expect(saveFindingsViewPreferences(preferences, storage)).toBe(true)
    expect(loadFindingsViewPreferences(storage)).toEqual(preferences)
  })
})
