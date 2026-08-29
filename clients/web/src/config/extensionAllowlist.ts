// Read at runtime from a <meta> tag (not inline <script>: the CSP is
// script-src 'self'). The same list drives the backend CSP + SSRF guard, so the
// browser trust gate can't drift into "trusted here but CSP-blocked".
const _meta =
  (typeof document !== 'undefined' &&
    document
      .querySelector('meta[name="vigil-extension-allowlist"]')
      ?.getAttribute('content')) ||
  ''
const _fromVite =
  (import.meta.env.VITE_EXTENSION_ORIGIN_ALLOWLIST as string | undefined) ?? ''

export const extensionOriginAllowlist: string[] = (_meta || _fromVite)
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)
