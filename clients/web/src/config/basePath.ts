// The context path is read at runtime from a <meta> tag the backend injects —
// a <meta>, not an inline <script>, because the CSP is script-src 'self'.
// Falls back to Vite's build-time BASE_URL. Empty string = served at the root.
const _meta =
  (typeof document !== 'undefined' &&
    document
      .querySelector('meta[name="vigil-base-path"]')
      ?.getAttribute('content')) ||
  ''
const _fromVite = (import.meta.env.BASE_URL || '').replace(/\/$/, '')
export const basePath: string = _meta || (_fromVite === '.' ? '' : _fromVite)
