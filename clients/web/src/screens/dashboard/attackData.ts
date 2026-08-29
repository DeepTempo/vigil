export type TimelineKind = 'finding' | 'case' | 'alert'

export interface TimelineEvent {
  id: string
  sev: 'critical' | 'high' | 'medium' | 'low'
  tech: string
  t: number
  kind: TimelineKind
}

export const TL_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
export const SEV_COLOR: Record<TimelineEvent['sev'], string> = {
  critical: 'var(--crit)',
  high: 'var(--high)',
  medium: 'var(--med)',
  low: 'var(--ok)',
}
