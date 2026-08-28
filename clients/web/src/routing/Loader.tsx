import '../styles.css'
import { useColorScheme } from '../contexts/ColorSchemeContext'
import { VigilMark } from '../shared/VigilLogo'
import { accentVars, loadAccent } from '../shared/accent'

export default function Loader({ label = 'Loading console…' }: { label?: string }) {
  const { scheme } = useColorScheme()
  // read straight from storage: no SocThemeProvider is mounted yet
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
