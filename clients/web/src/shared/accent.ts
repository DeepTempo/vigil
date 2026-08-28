/* Shared rather than shell/: routing/Loader and the login screen paint from
   these outside the console. */
import type { CSSProperties } from 'react'

export interface AccentState {
  /** null when a custom hex is in use */
  key: string | null
  a: string
  b: string
}

export const ACCENTS: Record<string, [string, string]> = {
  violet: ['#7d74f3', '#9a92f7'],
  cyan: ['#28a9bd', '#45c2d4'],
  emerald: ['#3aab74', '#54c08c'],
  coral: ['#e2705f', '#ec8a7b'],
}

export const ACCENT_SWATCHES: { key: string; color: string }[] = [
  { key: 'violet', color: '#7d74f3' },
  { key: 'cyan', color: '#28a9bd' },
  { key: 'emerald', color: '#3aab74' },
  { key: 'coral', color: '#e2705f' },
]

/** "#abc" / "abc" / "aabbcc" -> "#aabbcc"; null if invalid */
export function normHex(v: string): string | null {
  if (!v) return null
  let h = v.trim().replace(/^#/, '').toLowerCase()
  if (/^[0-9a-f]{3}$/.test(h)) h = h.split('').map((c) => c + c).join('')
  return /^[0-9a-f]{6}$/.test(h) ? '#' + h : null
}

export function lighten(hex: string, amt: number): string {
  const n = parseInt(hex.slice(1), 16)
  const r = n >> 16
  const g = (n >> 8) & 255
  const b = n & 255
  const mix = (c: number) => Math.round(c + (255 - c) * amt)
  return '#' + [mix(r), mix(g), mix(b)].map((c) => c.toString(16).padStart(2, '0')).join('')
}

export function accentVars(a: string, b: string): CSSProperties {
  return {
    '--accent': a,
    '--accent-2': b,
    '--accent-dim': a + '24',
    '--accent-line': a + '55',
  } as CSSProperties
}

export const ACCENT_KEY = 'soc.accent'
export const DEFAULT_ACCENT: AccentState = { key: 'violet', a: '#7d74f3', b: '#9a92f7' }

export function loadAccent(): AccentState {
  try {
    const raw = localStorage.getItem(ACCENT_KEY)
    if (raw) {
      const p = JSON.parse(raw) as Partial<AccentState>
      if (p && typeof p.a === 'string' && typeof p.b === 'string') {
        return { key: typeof p.key === 'string' ? p.key : null, a: p.a, b: p.b }
      }
    }
  } catch {
    /* empty */
  }
  return DEFAULT_ACCENT
}
