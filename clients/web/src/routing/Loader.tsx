/* ============================================================
   Route-transition loading screen — the Suspense fallback in
   App.tsx while the lazy console / login / setup chunks load, and
   what the route guards show while auth and first-run setup
   resolve. Themed via ColorSchemeContext and the persisted accent
   (shared/accent.ts), so it matches whatever renders once it mounts.
   ============================================================ */
import '../styles.css'
import { useColorScheme } from '../contexts/ColorSchemeContext'
import { VigilMark } from '../shared/VigilLogo'
import { accentVars, loadAccent } from '../shared/accent'

export default function Loader({ label = 'Loading console…' }: { label?: string }) {
  const { scheme } = useColorScheme()
  // the accent the user last picked, so the brand glyph + progress bar match
  // the console this is standing in for. Read straight from shared/accent.ts:
  // no SocThemeProvider is mounted yet.
  const accent = loadAccent()
  return (
    <div
      className="soc-console soc-loader"
      data-theme={scheme}
      style={accentVars(accent.a, accent.b)}
    >
      <div className="soc-loader-inner">
        <VigilMark className="soc-loader-mark" />
        <div className="soc-loader-track" />
        <div className="soc-loader-label">{label}</div>
      </div>
    </div>
  )
}
