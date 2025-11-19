import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import { Calendar, Filter, RefreshCcw, Search, Shield, UserRound } from 'lucide-react'

import { ActivityTimeline } from '@/components/activity/activity-timeline'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { useActivityHistory } from '@/hooks/use-activity-history'

export type AuditFocusOption = {
  id: string
  label: string
  description: string
  filters: {
    action?: string
    q?: string
  }
}

export type AuditActivityConsoleProps = {
  title?: string
  description?: string
  badgeLabel?: string
  icon?: LucideIcon
  focusOptions?: AuditFocusOption[]
  retentionHighlights?: string[]
  presetTitle?: string
  presetDescription?: string
  filtersTitle?: string
  filtersDescription?: string
  timelineTitle?: string
  timelineDescription?: string
  showBadge?: boolean
  showHeader?: boolean
  showRetentionHighlights?: boolean
  variant?: 'page' | 'embedded'
}

const DEFAULT_FOCUS_OPTIONS: AuditFocusOption[] = [
  { id: 'all', label: 'All activity', description: 'Everything retained under the security retention policy.', filters: {} },
  { id: 'auth', label: 'Authentication safeguards', description: 'Logins, lockouts, MFA enrollment, and reset flows.', filters: { action: 'auth.' } },
  { id: 'rbac', label: 'Roles & privileges', description: 'Role grants, permission changes, and user escalations.', filters: { action: 'admin.users' } },
  { id: 'config', label: 'Configuration changes', description: 'Settings toggles, navigation edits, and feature flags.', filters: { action: 'admin.settings' } },
]

const DEFAULT_RETENTION_NOTES = [
  '90-day searchable retention for system administrators, with exportable CSV snapshots.',
  '365-day cold storage for regulatory hold. Requests route through the compliance team.',
  'Audit viewers must hold system_admin + audit.viewer roles. Access is tracked in this log.',
  'Filters respect RBAC: staff without billing scope cannot query billing.audit actions.',
]

export function AuditActivityConsole({
  title = 'Audit logs & retention',
  description = 'Correlate privileged activity directly inside the Security & Access workspace.',
  badgeLabel = 'Security & Access',
  icon: Icon = Shield,
  focusOptions = DEFAULT_FOCUS_OPTIONS,
  retentionHighlights = DEFAULT_RETENTION_NOTES,
  presetTitle = 'Focus presets',
  presetDescription = 'Tune the timeline to predefined backend streams without writing complex filters.',
  filtersTitle = 'Filters',
  filtersDescription = 'Combine preset scopes with ad-hoc filters for investigations.',
  timelineTitle = 'Audit timeline',
  timelineDescription = 'Page through immutable audit rows replicated from the backend feed.',
  showBadge = true,
  showHeader = true,
  showRetentionHighlights = true,
  variant = 'page',
}: AuditActivityConsoleProps) {
  const [focusId, setFocusId] = useState<string>(() => focusOptions[0]?.id ?? '')
  const [query, setQuery] = useState('')
  const [action, setAction] = useState('')
  const [userId, setUserId] = useState('')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)

  useEffect(() => {
    const hasCurrent = focusOptions.some((option) => option.id === focusId)
    if (!hasCurrent && focusOptions[0]) {
      setFocusId(focusOptions[0].id)
    }
  }, [focusOptions, focusId])

  useEffect(() => {
    setPage(1)
  }, [focusId, query, action, userId, from, to])

  const activeFocus = useMemo(() => focusOptions.find((option) => option.id === focusId) ?? focusOptions[0] ?? null, [focusId, focusOptions])

  const filters = useMemo(() => ({
    q: query.trim() || activeFocus?.filters.q || undefined,
    action: action.trim() || activeFocus?.filters.action || undefined,
    userId: userId.trim() || undefined,
    from: from ? new Date(from).toISOString() : undefined,
    to: to ? new Date(to).toISOString() : undefined,
    page,
    pageSize,
  }), [query, action, userId, from, to, page, pageSize, activeFocus])

  const { data, loading, error, refresh } = useActivityHistory(filters)

  const totalPages = useMemo(() => {
    if (!data.pageSize) return 1
    return Math.max(1, Math.ceil((data.total || 0) / data.pageSize))
  }, [data.total, data.pageSize])

  const insights = useMemo(() => data.items.reduce((acc, entry) => {
    const actionName = entry.action || ''
    if (actionName.startsWith('auth.')) acc.auth += 1
    if (actionName.includes('lock')) acc.lockouts += 1
    if (actionName.startsWith('admin.settings')) acc.settings += 1
    return acc
  }, { auth: 0, lockouts: 0, settings: 0 }), [data.items])

  const chips = buildActiveChips({ query, action, userId, from, to }, {
    clearQuery: () => setQuery(''),
    clearAction: () => setAction(''),
    clearUser: () => setUserId(''),
    clearFrom: () => setFrom(''),
    clearTo: () => setTo(''),
  })

  const resetFilters = () => {
    setQuery('')
    setAction('')
    setUserId('')
    setFrom('')
    setTo('')
  }

  const spacingClass = variant === 'embedded' ? 'space-y-4' : 'space-y-6'
  const showFullHeader = showHeader && variant === 'page'

  return (
    <div className={spacingClass} data-variant={variant}>
      {showFullHeader ? (
        <div className="flex flex-wrap items-start gap-3">
          <Icon className="text-primary" />
          <div>
            <h1 className="text-2xl font-semibold">{title}</h1>
            <p className="text-sm text-muted-foreground">{description}</p>
          </div>
          {showBadge && badgeLabel ? (
            <Badge variant="outline" className="ml-auto">{badgeLabel}</Badge>
          ) : null}
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>{presetTitle}</CardTitle>
          <CardDescription>{presetDescription}</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 lg:grid-cols-2">
          {focusOptions.map(option => (
            <button
              key={option.id}
              type="button"
              onClick={() => setFocusId(option.id)}
              className={`rounded-lg border px-4 py-3 text-left transition ${focusId === option.id ? 'border-primary bg-primary/10 text-primary' : 'hover:border-primary/60'}`}
            >
              <div className="font-medium leading-tight">{option.label}</div>
              <p className="text-xs text-muted-foreground mt-1">{option.description}</p>
            </button>
          ))}
        </CardContent>
        <CardFooter className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
          <span>Preset action filter: {activeFocus?.filters.action ?? '—'}</span>
          <span>Preset search: {activeFocus?.filters.q ?? '—'}</span>
        </CardFooter>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{filtersTitle}</CardTitle>
          <CardDescription>{filtersDescription}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-2">
            <FilterInput label="Search" icon={<Search className="h-4 w-4" />} placeholder="Action, actor, IP, or custom text" value={query} onChange={setQuery} />
            <FilterInput label="Action contains" icon={<Filter className="h-4 w-4" />} placeholder={activeFocus?.filters.action ?? 'auth.'} value={action} onChange={setAction} />
            <FilterInput label="Actor" icon={<UserRound className="h-4 w-4" />} placeholder="User ID or email" value={userId} onChange={setUserId} />
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <FilterDate label="From" value={from} onChange={setFrom} />
            <FilterDate label="To" value={to} onChange={setTo} />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" size="sm" onClick={resetFilters}>Clear custom filters</Button>
            {chips.length ? (
              <div className="flex flex-wrap items-center gap-2">
                {chips.map(chip => (
                  <FilterChip key={chip.key} label={chip.label} onClear={chip.onClear} />
                ))}
              </div>
            ) : (
              <span className="text-xs text-muted-foreground">Using preset-only filters.</span>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-wrap items-center gap-3">
          <div>
            <CardTitle>{timelineTitle}</CardTitle>
            <CardDescription>{timelineDescription}</CardDescription>
          </div>
          <Button variant="ghost" size="sm" className="ml-auto" onClick={refresh}>
            <RefreshCcw className="mr-2 h-3.5 w-3.5" /> Refresh data
          </Button>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-3">
            <MetricCard label="Events in range" value={data.total.toLocaleString()} caption={`Page size ${data.pageSize || pageSize}`} />
            <MetricCard label="Auth signals this page" value={insights.auth.toString()} caption="Entries with auth.* actions" />
            <MetricCard label="Lockouts detected" value={insights.lockouts.toString()} caption="Events referencing lock or block" />
          </div>
        </CardContent>
        <CardContent>
          <ActivityTimeline entries={data.items} loading={loading} error={error} onRetry={refresh} />
        </CardContent>
        <CardFooter className="flex flex-wrap items-center gap-2 text-sm">
          <span>Page {data.page ?? page} of {totalPages}</span>
          <span className="text-muted-foreground">Preset: {activeFocus?.label ?? '—'}</span>
          <div className="ml-auto flex items-center gap-2">
            <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage(p => Math.max(1, p - 1))}>Prev</Button>
            <Button size="sm" variant="outline" disabled={page >= totalPages} onClick={() => setPage(p => Math.min(totalPages, p + 1))}>Next</Button>
            <select aria-label="Page size" value={pageSize} onChange={event => { setPage(1); setPageSize(Number(event.target.value)) }} className="rounded-md border px-2 py-1 text-sm">
              {[25, 50, 100].map(size => (
                <option key={size} value={size}>{size} / page</option>
              ))}
            </select>
          </div>
        </CardFooter>
      </Card>

      {showRetentionHighlights && retentionHighlights.length ? (
        <Card>
          <CardHeader>
            <CardTitle>Retention & access policy</CardTitle>
            <CardDescription>Snapshot pulled from the admin operations playbook.</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="list-disc space-y-2 pl-5 text-sm text-muted-foreground">
              {retentionHighlights.map(item => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </CardContent>
        </Card>
      ) : null}
    </div>
  )
}

export const DEFAULT_AUDIT_FOCUS_OPTIONS = DEFAULT_FOCUS_OPTIONS
export const DEFAULT_AUDIT_RETENTION_NOTES = DEFAULT_RETENTION_NOTES

function FilterInput({ label, icon, placeholder, value, onChange }: { label: string; icon: ReactNode; placeholder: string; value: string; onChange: (next: string) => void }) {
  return (
    <label className="flex flex-col gap-1 text-sm">
      <span className="text-xs uppercase text-muted-foreground">{label}</span>
      <span className="flex items-center gap-2 rounded-md border px-2 py-1.5">
        {icon}
        <input className="flex-1 bg-transparent outline-none" placeholder={placeholder} value={value} onChange={event => onChange(event.target.value)} />
      </span>
    </label>
  )
}

function FilterDate({ label, value, onChange }: { label: string; value: string; onChange: (next: string) => void }) {
  return (
    <label className="flex flex-col gap-1 text-sm">
      <span className="text-xs uppercase text-muted-foreground">{label}</span>
      <span className="flex items-center gap-2 rounded-md border px-2 py-1.5">
        <Calendar className="h-4 w-4" />
        <input type="datetime-local" className="flex-1 bg-transparent outline-none" value={value} onChange={event => onChange(event.target.value)} />
      </span>
    </label>
  )
}

function MetricCard({ label, value, caption }: { label: string; value: string; caption: string }) {
  return (
    <div className="rounded-lg border p-4">
      <div className="text-xs uppercase text-muted-foreground">{label}</div>
      <div className="text-2xl font-semibold mt-1">{value}</div>
      <div className="text-xs text-muted-foreground mt-1">{caption}</div>
    </div>
  )
}

type ChipDescriptor = { key: string; label: string; onClear?: () => void }

function FilterChip({ label, onClear }: { label: string; onClear?: () => void }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full border px-3 py-1 text-xs">
      {label}
      {onClear ? (
        <button type="button" onClick={onClear} className="text-muted-foreground hover:text-foreground">×</button>
      ) : null}
    </span>
  )
}

function buildActiveChips(values: { query: string; action: string; userId: string; from: string; to: string }, handlers: { clearQuery: () => void; clearAction: () => void; clearUser: () => void; clearFrom: () => void; clearTo: () => void }) {
  const chips: ChipDescriptor[] = []
  if (values.query.trim()) chips.push({ key: 'q', label: `Search: ${values.query.trim()}`, onClear: handlers.clearQuery })
  if (values.action.trim()) chips.push({ key: 'action', label: `Action: ${values.action.trim()}`, onClear: handlers.clearAction })
  if (values.userId.trim()) chips.push({ key: 'user', label: `Actor: ${values.userId.trim()}`, onClear: handlers.clearUser })
  if (values.from) chips.push({ key: 'from', label: `From ${formatChipDate(values.from)}`, onClear: handlers.clearFrom })
  if (values.to) chips.push({ key: 'to', label: `To ${formatChipDate(values.to)}`, onClear: handlers.clearTo })
  return chips
}

function formatChipDate(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}
