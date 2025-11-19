import type { JSX } from 'react'
import { AlertTriangle, BadgeInfo, ShieldAlert } from 'lucide-react'
import type { AuditTimelineEntry } from '@/services/interfaces/types'
import { cn } from '@/lib/utils'

const severityClasses: Record<string, string> = {
  info: 'bg-sky-50 text-sky-800 border-sky-100',
  warning: 'bg-amber-50 text-amber-800 border-amber-100',
  critical: 'bg-rose-50 text-rose-800 border-rose-100',
}

const severityIcons: Record<string, JSX.Element> = {
  info: <BadgeInfo className="h-4 w-4" />,
  warning: <AlertTriangle className="h-4 w-4" />,
  critical: <ShieldAlert className="h-4 w-4" />,
}

export type ActivityTimelineProps = {
  entries: AuditTimelineEntry[]
  loading?: boolean
  error?: string | null
  onRetry?: () => void
  emptyState?: React.ReactNode
  className?: string
}

export function ActivityTimeline({ entries, loading, error, onRetry, emptyState, className }: ActivityTimelineProps) {
  return (
    <div className={cn('rounded-xl border bg-card/40 p-4', className)}>
      {loading && (
        <div className="py-8 text-center text-sm text-muted-foreground">Loading activity…</div>
      )}
      {error && !loading && (
        <div className="flex flex-col items-center gap-2 py-6 text-center text-sm text-red-600">
          <p>{error}</p>
          {onRetry && <button className="rounded-md border px-3 py-1.5 text-xs" onClick={onRetry}>Retry</button>}
        </div>
      )}
      {!loading && !error && entries.length === 0 && (
        <div className="py-6 text-center text-sm text-muted-foreground">
          {emptyState ?? 'No activity recorded for the selected filters.'}
        </div>
      )}
      {!loading && !error && entries.length > 0 && (
        <ol className="relative border-l border-border/60">
          {entries.map((entry, idx) => (
            <li key={entry.id ?? `${entry.action}-${idx}`} className="mb-8 ml-4 last:mb-0">
              <span className="absolute -left-1.5 flex h-3 w-3 items-center justify-center rounded-full bg-background ring-4 ring-background" />
              <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                <span>{new Date(entry.createdAt).toLocaleString()}</span>
                <SeverityBadge severity={entry.severity} />
              </div>
              <div className="mt-2 flex flex-wrap items-start gap-3">
                <AvatarBubble label={entry.actor?.initials ?? entry.actor?.name ?? entry.actor?.email ?? '—'} />
                <div className="space-y-1 text-sm">
                  <div className="font-medium text-foreground">{entry.description}</div>
                  <div className="text-xs text-muted-foreground">
                    {entry.actor?.name || entry.actor?.email || entry.actor?.id || 'System'}
                    {entry.target?.label && (
                      <>
                        {' '}→ <span className="font-medium">{entry.target.label}</span>
                      </>
                    )}
                  </div>
                  <MetadataChips entry={entry} />
                </div>
              </div>
              {entry.metadata && (
                <details className="mt-3 rounded-lg border bg-muted/30 p-3 text-xs">
                  <summary className="cursor-pointer text-muted-foreground">Metadata</summary>
                  <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap text-[11px]">{formatMetadata(entry.metadata)}</pre>
                </details>
              )}
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}

function SeverityBadge({ severity }: { severity?: string }) {
  const key = severity ?? 'info'
  const icon = severityIcons[key] ?? severityIcons.info
  return (
    <span className={cn('inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium', severityClasses[key] ?? severityClasses.info)}>
      {icon}
      {key.toUpperCase()}
    </span>
  )
}

function AvatarBubble({ label }: { label: string }) {
  const display = label.trim().slice(0, 2).toUpperCase()
  return (
    <span className="inline-flex h-9 w-9 items-center justify-center rounded-full bg-muted text-xs font-semibold text-muted-foreground">
      {display || '—'}
    </span>
  )
}

function MetadataChips({ entry }: { entry: AuditTimelineEntry }) {
  return (
    <div className="flex flex-wrap gap-2 text-[11px] text-muted-foreground">
      {entry.ipAddress && <span className="rounded-full border px-2 py-0.5">IP {entry.ipAddress}</span>}
      {entry.userAgent && <span className="rounded-full border px-2 py-0.5">UA {truncate(entry.userAgent)}</span>}
      {entry.tags?.slice(0, 4).map(tag => (
        <span key={tag} className="rounded-full border px-2 py-0.5">{tag}</span>
      ))}
    </div>
  )
}

function truncate(value: string, len = 38) {
  if (value.length <= len) return value
  return `${value.slice(0, len)}…`
}

function formatMetadata(meta: unknown) {
  try {
    return JSON.stringify(meta ?? null, null, 2)
  } catch {
    return String(meta)
  }
}

export default ActivityTimeline
