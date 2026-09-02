import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { WatchersCard, SLACard } from './CaseSections'
import { casesApi } from '../../services/api'

/**
 * The watchers card read `added_at`, but the API sends `created_at` — so
 * `fmtD` was always called with `undefined` and every row rendered
 * "Watching since —". It failed quietly: `fmtD` guards falsy input, and the
 * `?` on the interface field kept TypeScript happy, so nothing surfaced the
 * mismatch. Fixed in #584; this pins it. See #561.
 */

/* `fmtD` formats in local time, so an unpinned TZ makes the expected date
   depend on where the suite runs (UTC-10 rolls 09:14Z back a day). */
vi.stubEnv('TZ', 'UTC')

vi.mock('../../services/api', () => ({
  casesApi: {
    getWatchers: vi.fn(),
    addWatcher: vi.fn(),
    removeWatcher: vi.fn(),
    getSLA: vi.fn(),
    pauseSLA: vi.fn(),
    resumeSLA: vi.fn(),
  },
}))

/** The shape `CaseWatcherSchema` dumps (core/storage/schemas/case_entities.py). */
const WATCHER_ROW = {
  case_id: 'case-2026-0142',
  user_id: 'analyst@example.com',
  notification_preferences: {},
  created_at: '2026-06-15T09:14:00Z',
}

/** The shape `CaseSLAStatusSchema` records (CaseSLAService.get_sla_status). */
const SLA_STATUS = {
  case_id: 'case-2026-0142',
  sla_policy_id: 'sla-high',
  response_due: '2026-06-15T11:14:00Z',
  resolution_due: '2026-06-16T09:14:00Z',
  response_remaining_seconds: 3600,
  resolution_remaining_seconds: 7200,
  response_percent_elapsed: 40,
  resolution_percent_elapsed: 25,
  response_completed: false,
  resolution_completed: false,
  response_sla_met: null,
  resolution_sla_met: null,
  is_breached: false,
  breach_type: null,
  is_paused: false,
  health_status: 'healthy',
}

beforeEach(() => {
  vi.mocked(casesApi.getWatchers).mockResolvedValue({
    data: { watchers: [WATCHER_ROW] },
  } as never)
  vi.mocked(casesApi.getSLA).mockResolvedValue({
    data: SLA_STATUS,
  } as never)
})

describe('WatchersCard', () => {
  it('renders the date the watcher started watching', async () => {
    render(<WatchersCard caseId="case-2026-0142" />)

    await waitFor(() =>
      expect(screen.getByText('analyst@example.com')).toBeInTheDocument(),
    )

    expect(screen.getByText(/Watching since Jun 15, 2026/)).toBeInTheDocument()
  })

  it('does not fall back to the em-dash placeholder for a real timestamp', async () => {
    // The precise pre-fix symptom. Asserting only the date above would still
    // pass if the component rendered both, so pin the absence too.
    render(<WatchersCard caseId="case-2026-0142" />)

    await waitFor(() =>
      expect(screen.getByText('analyst@example.com')).toBeInTheDocument(),
    )

    expect(screen.queryByText('Watching since —')).not.toBeInTheDocument()
  })

  it('still shows the placeholder when the API omits the timestamp', async () => {
    // `CaseWatcherSchema.created_at` is optional, so the field can be absent
    // from the payload — that path must keep degrading gracefully rather than
    // rendering "Invalid Date".
    vi.mocked(casesApi.getWatchers).mockResolvedValue({
      data: { watchers: [{ ...WATCHER_ROW, created_at: undefined }] },
    } as never)

    render(<WatchersCard caseId="case-2026-0142" />)

    await waitFor(() =>
      expect(screen.getByText('analyst@example.com')).toBeInTheDocument(),
    )

    expect(screen.getByText('Watching since —')).toBeInTheDocument()
  })
})

describe('SLACard', () => {
  it('renders the computed SLA status payload, not an invented envelope', async () => {
    render(<SLACard caseId="case-2026-0142" />)

    await waitFor(() => expect(screen.getByText('healthy')).toBeInTheDocument())

    expect(screen.getByText('sla-high')).toBeInTheDocument()
    expect(screen.getByText('Response due')).toBeInTheDocument()
    expect(screen.getByText('Resolution due')).toBeInTheDocument()
    expect(screen.queryByText('No SLA policy attached')).not.toBeInTheDocument()
  })

  it('treats a 404 as no policy rather than an error', async () => {
    vi.mocked(casesApi.getSLA).mockRejectedValueOnce({ response: { status: 404 } })
    render(<SLACard caseId="case-2026-0142" />)

    await waitFor(() =>
      expect(screen.getByText('No SLA policy attached')).toBeInTheDocument(),
    )
  })
})
