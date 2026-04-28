import { useLayoutEffect, useRef, useState } from 'react'
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  SelectChangeEvent,
  Snackbar,
  Stack,
  Tooltip,
  Typography,
} from '@mui/material'
import {
  Fullscreen as FullscreenIcon,
  FullscreenExit as FullscreenExitIcon,
  PlayArrow as PlayIcon,
} from '@mui/icons-material'
import {
  useVStrikeIframe,
  useVStrikeIframeInternals,
} from '../../contexts/VStrikeIframeContext'
import { buildKillchainSteps } from './buildKillchainSteps'

interface Rect {
  top: number
  left: number
  width: number
  height: number
}

const HIDDEN_RECT: Rect = { top: -10000, left: -10000, width: 1, height: 1 }

const TOP_BAR_OFFSET_PX = 64

/**
 * Host for the single, app-wide VStrike iframe.
 *
 * Mounted once at the layout root. Owns the `<iframe>` element and tracks the
 * currently registered anchor (a `<div>` rendered by whichever surface wants
 * to display VStrike). The iframe is positioned absolutely over the anchor's
 * bounding rect via a `ResizeObserver` + `scroll` listener; it never unmounts,
 * so the VStrike session inside the iframe survives every navigation.
 *
 * The toolbar (network selector + Play + Fullscreen) floats at the top of the
 * iframe rect and is only visible when an anchor is active.
 */
export default function VStrikeIframeHost() {
  const ctx = useVStrikeIframe()
  const internals = useVStrikeIframeInternals()
  const iframeRef = useRef<HTMLIFrameElement | null>(null)
  const [rect, setRect] = useState<Rect>(HIDDEN_RECT)
  const [snackbar, setSnackbar] = useState<{
    severity: 'success' | 'error' | 'info'
    message: string
  } | null>(null)

  const anchor = internals.activeAnchor
  const fullscreen = ctx.fullscreen
  const visible = anchor !== null

  // Track the anchor's bounding rect. ResizeObserver covers anchor resize +
  // layout shifts; window resize/scroll covers viewport changes.
  useLayoutEffect(() => {
    if (fullscreen) {
      const update = () => {
        setRect({
          top: TOP_BAR_OFFSET_PX,
          left: 0,
          width: window.innerWidth,
          height: window.innerHeight - TOP_BAR_OFFSET_PX,
        })
      }
      update()
      window.addEventListener('resize', update)
      return () => window.removeEventListener('resize', update)
    }

    if (!anchor) {
      setRect(HIDDEN_RECT)
      return
    }

    const update = () => {
      const r = anchor.getBoundingClientRect()
      setRect({ top: r.top, left: r.left, width: r.width, height: r.height })
    }
    update()

    const ro = new ResizeObserver(update)
    ro.observe(anchor)
    // Catch scroll inside any ancestor (case dialog body, etc.).
    window.addEventListener('scroll', update, true)
    window.addEventListener('resize', update)
    return () => {
      ro.disconnect()
      window.removeEventListener('scroll', update, true)
      window.removeEventListener('resize', update)
    }
  }, [anchor, fullscreen])

  // Bridge the iframe's `onLoad` event into the context (so it can apply the
  // pending network selection once the VStrike app is ready inside the frame).
  const handleLoad = () => {
    internals.handleIframeLoad()
  }

  const handleNetworkChange = (event: SelectChangeEvent<string>) => {
    ctx.setNetwork(event.target.value)
  }

  const handlePlay = async () => {
    const steps = buildKillchainSteps(ctx.activeFindings)
    if (steps.length === 0) {
      setSnackbar({
        severity: 'info',
        message:
          'No kill-chain to play — none of the visible findings carry VStrike attack-path data.',
      })
      return
    }
    const result = await ctx.triggerKillchain(steps)
    if (result.ok) {
      setSnackbar({
        severity: 'success',
        message: `VStrike is replaying ${steps.length} step${
          steps.length === 1 ? '' : 's'
        }.`,
      })
      return
    }
    setSnackbar({ severity: 'error', message: result.message })
  }

  const playDisabled =
    ctx.state !== 'ready' ||
    !ctx.hasAnchor ||
    ctx.activeFindings.length === 0

  // Error overlay positioned over the anchor.
  if (ctx.error && visible) {
    return (
      <Paper
        variant="outlined"
        sx={{
          position: 'fixed',
          top: rect.top,
          left: rect.left,
          width: rect.width,
          height: rect.height,
          zIndex: fullscreen ? 1300 : 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          p: 3,
          pointerEvents: 'auto',
        }}
      >
        <Stack spacing={2} alignItems="center" maxWidth={520}>
          <Alert severity={ctx.error.missingCredentials ? 'warning' : 'error'}>
            {ctx.error.message}
          </Alert>
          {ctx.error.missingCredentials ? (
            <Button
              variant="outlined"
              href="/settings"
              onClick={(e) => {
                e.preventDefault()
                window.location.assign('/settings')
              }}
            >
              Open Settings
            </Button>
          ) : (
            <Button variant="outlined" onClick={ctx.reload}>
              Retry
            </Button>
          )}
        </Stack>
      </Paper>
    )
  }

  return (
    <>
      <Box
        sx={{
          position: 'fixed',
          top: rect.top,
          left: rect.left,
          width: rect.width,
          height: rect.height,
          // The iframe is always mounted, even when no anchor is active —
          // visibility hidden + pointer-events none + offscreen rect parks it
          // without unmounting (which would lose the VStrike session).
          visibility: visible ? 'visible' : 'hidden',
          pointerEvents: visible ? 'auto' : 'none',
          opacity: visible ? 1 : 0,
          zIndex: fullscreen ? 1300 : 2,
          transition: 'opacity 120ms ease',
          display: 'flex',
          flexDirection: 'column',
          bgcolor: 'background.paper',
          // No border in fullscreen; subtle border otherwise to match the
          // case-dialog look.
          border: fullscreen ? 0 : 1,
          borderColor: 'divider',
        }}
      >
        {/* Toolbar */}
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            px: 1,
            py: 0.5,
            borderBottom: 1,
            borderColor: 'divider',
            bgcolor: 'background.paper',
            minHeight: 44,
          }}
        >
          <Typography variant="subtitle2" sx={{ pl: 1 }}>
            VStrike Network View
          </Typography>
          <Stack direction="row" spacing={1} alignItems="center">
            <FormControl
              size="small"
              sx={{ minWidth: 220 }}
              disabled={ctx.state !== 'ready'}
            >
              <InputLabel id="vstrike-network-label">Network</InputLabel>
              <Select
                labelId="vstrike-network-label"
                label="Network"
                value={ctx.selectedNetwork}
                onChange={handleNetworkChange}
                displayEmpty
              >
                <MenuItem value="">
                  <em>
                    {ctx.networks.length ? 'Select a network…' : 'No networks'}
                  </em>
                </MenuItem>
                {ctx.networks.map((opt) => (
                  <MenuItem key={opt.id} value={opt.id}>
                    {opt.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <Tooltip
              title={
                playDisabled
                  ? 'Play requires VStrike-enriched findings in this view.'
                  : 'Replay the kill-chain in the VStrike view'
              }
            >
              <span>
                <IconButton
                  size="small"
                  onClick={handlePlay}
                  disabled={playDisabled}
                  aria-label="Play kill-chain"
                >
                  <PlayIcon />
                </IconButton>
              </span>
            </Tooltip>
            <Tooltip title={fullscreen ? 'Exit full screen' : 'Full screen'}>
              <IconButton
                size="small"
                onClick={() => ctx.setFullscreen(!fullscreen)}
                aria-label={fullscreen ? 'Exit full screen' : 'Full screen'}
              >
                {fullscreen ? <FullscreenExitIcon /> : <FullscreenIcon />}
              </IconButton>
            </Tooltip>
          </Stack>
        </Box>

        {/* Iframe + loading overlay */}
        <Box sx={{ flex: 1, position: 'relative', minHeight: 0 }}>
          {ctx.state === 'pending' && (
            <Box
              sx={{
                position: 'absolute',
                inset: 0,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                bgcolor: 'background.default',
                zIndex: 1,
              }}
            >
              <CircularProgress />
            </Box>
          )}
          {ctx.iframeUrl && (
            <iframe
              ref={iframeRef}
              src={ctx.iframeUrl}
              title="VStrike Network Visualization"
              onLoad={handleLoad}
              sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
              referrerPolicy="no-referrer"
              style={{
                border: 0,
                width: '100%',
                height: '100%',
                display: 'block',
              }}
            />
          )}
        </Box>
      </Box>
      <Snackbar
        open={snackbar !== null}
        autoHideDuration={5000}
        onClose={() => setSnackbar(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        {snackbar ? (
          <Alert
            severity={snackbar.severity}
            onClose={() => setSnackbar(null)}
            sx={{ maxWidth: 560 }}
          >
            {snackbar.message}
          </Alert>
        ) : undefined}
      </Snackbar>
    </>
  )
}

