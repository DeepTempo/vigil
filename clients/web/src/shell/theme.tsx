/* Layered over ColorSchemeContext on purpose; do not merge them. This provider
   is mounted twice in independent trees (SocConsole, LoginScreen) and
   routing/Loader needs the scheme with none of them above it, so the scheme has
   to sit higher and outlive the browser. */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { useColorScheme } from '../contexts/ColorSchemeContext'
import {
  ACCENTS,
  ACCENT_KEY,
  lighten,
  loadAccent,
  normHex,
  type AccentState,
} from '../shared/accent'
import { BG_PRESETS, defaultBaseForScheme, isDarkBase, normHex as normBgHex } from './bg'

export type { AccentState }

export interface BgState {
  key: string | null
  /** the rest of the surface/line/text ramp is derived from this */
  base: string
}

interface SocThemeValue {
  scheme: 'light' | 'dark'
  setScheme: (scheme: 'light' | 'dark') => void
  accent: AccentState
  setPreset: (key: string) => void
  /** false when the hex is invalid */
  setHex: (hex: string) => boolean
  bg: BgState
  /** also drives scheme, from the base's lightness */
  setBgPreset: (key: string) => void
  /** also drives scheme; false when the hex is invalid */
  setBgHex: (hex: string) => boolean
}

const DEFAULT_BG: BgState = { key: 'slate', base: BG_PRESETS.slate }
const BG_KEY = 'soc.bg'

function loadBg(): BgState {
  try {
    const raw = localStorage.getItem(BG_KEY)
    if (raw) {
      const p = JSON.parse(raw) as Partial<BgState>
      if (p && typeof p.base === 'string') {
        return { key: typeof p.key === 'string' ? p.key : null, base: p.base }
      }
    }
  } catch {
    /* empty */
  }
  return DEFAULT_BG
}

const SocThemeContext = createContext<SocThemeValue | undefined>(undefined)

export function useSocTheme(): SocThemeValue {
  const ctx = useContext(SocThemeContext)
  if (!ctx) throw new Error('useSocTheme must be used within SocThemeProvider')
  return ctx
}

export function SocThemeProvider({ children }: { children: ReactNode }) {
  const { scheme, setScheme } = useColorScheme()
  const [accent, setAccent] = useState<AccentState>(loadAccent)
  const [bg, setBg] = useState<BgState>(loadBg)

  useEffect(() => {
    try {
      localStorage.setItem(ACCENT_KEY, JSON.stringify(accent))
    } catch {
      /* empty */
    }
  }, [accent])

  useEffect(() => {
    try {
      localStorage.setItem(BG_KEY, JSON.stringify(bg))
    } catch {
      /* empty */
    }
  }, [bg])

  // The bg setters push scheme; this is the other direction, for a scheme
  // changed outside the provider (backend load, Setup).
  useEffect(() => {
    if (isDarkBase(bg.base) !== (scheme === 'dark')) {
      setBg(defaultBaseForScheme(scheme))
    }
    // intentionally only reacts to `scheme`; reacting to `bg` would fight the setters
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scheme])

  const setPreset = useCallback((key: string) => {
    const preset = ACCENTS[key]
    if (!preset) return
    const [a, b] = preset
    setAccent({ key, a, b })
  }, [])

  const setHex = useCallback((input: string): boolean => {
    const a = normHex(input)
    if (!a) return false
    setAccent({ key: null, a, b: lighten(a, 0.22) })
    return true
  }, [])

  const setBgPreset = useCallback(
    (key: string) => {
      const base = BG_PRESETS[key]
      if (!base) return
      setBg({ key, base })
      const next = isDarkBase(base) ? 'dark' : 'light'
      if (next !== scheme) setScheme(next)
    },
    [scheme, setScheme],
  )

  const setBgHex = useCallback(
    (input: string): boolean => {
      const base = normBgHex(input)
      if (!base) return false
      setBg({ key: null, base })
      const next = isDarkBase(base) ? 'dark' : 'light'
      if (next !== scheme) setScheme(next)
      return true
    },
    [scheme, setScheme],
  )

  const value = useMemo<SocThemeValue>(
    () => ({ scheme, setScheme, accent, setPreset, setHex, bg, setBgPreset, setBgHex }),
    [scheme, setScheme, accent, setPreset, setHex, bg, setBgPreset, setBgHex],
  )

  return <SocThemeContext.Provider value={value}>{children}</SocThemeContext.Provider>
}
