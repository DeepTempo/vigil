import { format, isValid, parseISO } from 'date-fns'

function toDate(value: Date | string): Date | null {
  if (value instanceof Date) {
    return isValid(value) ? value : null
  }
  const iso = parseISO(value)
  if (isValid(iso)) return iso
  const fallback = new Date(value)
  return isValid(fallback) ? fallback : null
}

export function formatEventDateTime(value: Date | string | null | undefined): string {
  if (value == null || value === '') return '—'
  const d = toDate(value)
  return d ? format(d, 'yyyy-MM-dd HH:mm:ss') : '—'
}

export function formatEventTimeOnly(value: Date | string | null | undefined): string {
  if (value == null || value === '') return '—'
  const d = toDate(value)
  return d ? format(d, 'HH:mm:ss') : '—'
}

export function formatDownloadTimestamp(): string {
  return format(new Date(), 'yyyy-MM-dd-HHmmss')
}
