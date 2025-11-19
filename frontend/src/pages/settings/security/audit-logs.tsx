import { type ReactNode, useEffect, useState } from 'react'
import { Shield } from 'lucide-react'

import { AuditActivityConsole } from '@/components/audit/audit-activity-console'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from '@/components/ui/sheet'
import { Textarea } from '@/components/ui/textarea'
import { useAdminSettings, useSaveAdminSettings } from '@/services/hooks/admin'
import type { AuditAlertSettings, AuditExportSettings, AuditReviewerSettings, AuditRetentionSettings, AuditWebhookTarget } from '@/types/audit-settings'
import {
  DEFAULT_AUDIT_ALERTS,
  DEFAULT_AUDIT_EXPORTS,
  DEFAULT_AUDIT_RETENTION,
  DEFAULT_AUDIT_REVIEWERS,
  normalizeAuditAlerts,
  normalizeAuditExports,
  normalizeAuditRetention,
  normalizeAuditReviewers,
} from '@/types/audit-settings'

type SectionKey = 'retention' | 'exports' | 'alerts' | 'reviewers'

export default function SecurityAuditLogsSettingsPage() {
  const settingsQuery = useAdminSettings()
  const saveMutation = useSaveAdminSettings()

  const [retention, setRetention] = useState<AuditRetentionSettings>(DEFAULT_AUDIT_RETENTION)
  const [exportControls, setExportControls] = useState<AuditExportSettings>(DEFAULT_AUDIT_EXPORTS)
  const [alerts, setAlerts] = useState<AuditAlertSettings>(DEFAULT_AUDIT_ALERTS)
  const [reviewers, setReviewers] = useState<AuditReviewerSettings>(DEFAULT_AUDIT_REVIEWERS)
  const [saving, setSaving] = useState<SectionKey | null>(null)
  const [consoleOpen, setConsoleOpen] = useState(false)

  useEffect(() => {
    const audit = settingsQuery.data?.audit ?? {}
    setRetention(normalizeAuditRetention(audit.retention))
    setExportControls(normalizeAuditExports(audit.exports))
    setAlerts(normalizeAuditAlerts(audit.alerts))
    setReviewers(normalizeAuditReviewers(audit.reviewers))
  }, [settingsQuery.data])

  const saveSection = async (section: SectionKey) => {
    try {
      setSaving(section)
      switch (section) {
        case 'retention':
          await saveMutation.mutateAsync({ category: 'audit', entries: [{ key: 'retention', value: retention }] })
          break
        case 'exports':
          await saveMutation.mutateAsync({ category: 'audit', entries: [{ key: 'exports', value: exportControls }] })
          break
        case 'alerts':
          await saveMutation.mutateAsync({ category: 'audit', entries: [{ key: 'alerts', value: alerts }] })
          break
        case 'reviewers':
          await saveMutation.mutateAsync({ category: 'audit', entries: [{ key: 'reviewers', value: reviewers }] })
          break
      }
    } finally {
      setSaving(null)
    }
  }

  const loading = settingsQuery.isLoading
  const error = settingsQuery.error as Error | null

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start gap-3">
        <Shield className="text-primary" />
        <div>
          <h1 className="text-2xl font-semibold">Audit log configuration</h1>
          <p className="text-sm text-muted-foreground">Retention, export approval, alert routing, and reviewer policies sourced from the admin operations playbook.</p>
        </div>
        <Badge variant="outline" className="ml-auto">Security & Access</Badge>
      </div>

      {error ? (
        <Alert variant="destructive">
          <AlertTitle>Unable to load audit settings</AlertTitle>
          <AlertDescription>{error.message}</AlertDescription>
        </Alert>
      ) : null}

      <div className="grid gap-6 xl:grid-cols-[2fr_1fr]">
        <div className="space-y-6">
          <RetentionCard
            value={retention}
            disabled={loading || saving === 'retention'}
            onChange={setRetention}
            onSave={() => saveSection('retention')}
          />

          <ExportControlsCard
            value={exportControls}
            disabled={loading || saving === 'exports'}
            onChange={setExportControls}
            onSave={() => saveSection('exports')}
          />

          <AlertRoutingCard
            value={alerts}
            disabled={loading || saving === 'alerts'}
            onChange={setAlerts}
            onSave={() => saveSection('alerts')}
          />

          <ReviewersCard
            value={reviewers}
            disabled={loading || saving === 'reviewers'}
            onChange={setReviewers}
            onSave={() => saveSection('reviewers')}
          />
        </div>

        <div className="space-y-6">
          <Sheet open={consoleOpen} onOpenChange={setConsoleOpen}>
            <Card>
              <CardHeader>
                <CardTitle>Live audit console</CardTitle>
                <CardDescription>Launch the investigative timeline in a slide-over without losing your place.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3 text-sm text-muted-foreground">
                <p>Use the console to verify retention toggles, monitor authentication spikes, or capture exports for leadership reviews.</p>
                <p>The sheet remembers your filters while you tweak policies on this page.</p>
              </CardContent>
              <CardFooter className="flex flex-wrap items-center gap-3">
                <SheetTrigger asChild>
                  <Button onClick={() => setConsoleOpen(true)}>Open live console</Button>
                </SheetTrigger>
                <span className="text-xs text-muted-foreground">Shortcut: press Esc to close once open.</span>
              </CardFooter>
            </Card>
            <SheetContent side="right" className="w-full p-0 sm:max-w-3xl">
              <SheetHeader className="border-b px-6 py-4">
                <SheetTitle>Live audit console</SheetTitle>
                <SheetDescription>Investigate high-risk activity while staying within Security &amp; Access settings.</SheetDescription>
              </SheetHeader>
              <div className="flex-1 overflow-y-auto px-6 pb-6">
                <AuditActivityConsole
                  showHeader={false}
                  showBadge={false}
                  showRetentionHighlights={false}
                  variant="embedded"
                  title="Audit logs"
                  description="Live feed"
                />
              </div>
            </SheetContent>
          </Sheet>

          <Card>
            <CardHeader>
              <CardTitle>Admin operations playbook highlights</CardTitle>
              <CardDescription>Use these guardrails when adjusting policies.</CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="list-disc space-y-2 pl-5 text-sm text-muted-foreground">
                <li>Search retention is 90 days; cold storage is 365 days with purge at 545.</li>
                <li>Exports require dual-approval from system_admin + audit.reviewer and expire after 72 hours.</li>
                <li>Critical alerts page the duty officer and fire Slack webhooks; ping slack#security.</li>
                <li>Two reviewer pools rotate weekly; escalation triggers escalations after 4 hours of silence.</li>
              </ul>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}

type RetentionCardProps = {
  value: AuditRetentionSettings
  disabled?: boolean
  onChange: (next: AuditRetentionSettings) => void
  onSave: () => void
}

function RetentionCard({ value, disabled, onChange, onSave }: RetentionCardProps) {
  const update = (patch: Partial<AuditRetentionSettings>) => onChange({ ...value, ...patch })
  return (
    <Card>
      <CardHeader>
        <CardTitle>Retention policy</CardTitle>
        <CardDescription>Controls for searchable vs. cold storage windows plus legal hold routing.</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4 md:grid-cols-2">
        <Field label="Hot tier (searchable days)" htmlFor="retention-hot" hint="Live queries + exports use this window.">
          <Input
            id="retention-hot"
            type="number"
            min={1}
            value={value.hotTierDays}
            disabled={disabled}
            onChange={(event) => update({ hotTierDays: Number(event.target.value) })}
          />
        </Field>
        <Field label="Cold storage (days)" htmlFor="retention-cold" hint="Cold tier replicates to long-term storage.">
          <Input
            id="retention-cold"
            type="number"
            min={value.hotTierDays}
            value={value.coldTierDays}
            disabled={disabled}
            onChange={(event) => update({ coldTierDays: Number(event.target.value) })}
          />
        </Field>
        <Field label="Auto purge (days)" htmlFor="retention-purge" hint="Applied when no legal hold is active.">
          <Input
            id="retention-purge"
            type="number"
            min={value.coldTierDays}
            value={value.purgeAfterDays}
            disabled={disabled}
            onChange={(event) => update({ purgeAfterDays: Number(event.target.value) })}
          />
        </Field>
        <Field label="Legal hold contacts" htmlFor="retention-hold" hint="One email per line. Triggers hold workflows.">
          <Textarea
            id="retention-hold"
            rows={4}
            disabled={disabled}
            value={value.legalHoldContacts.join('\n')}
            onChange={(event) => update({ legalHoldContacts: toList(event.target.value) })}
          />
        </Field>
      </CardContent>
      <CardFooter>
        <Button size="sm" onClick={onSave} disabled={disabled}>{disabled ? 'Saving…' : 'Save retention policy'}</Button>
      </CardFooter>
    </Card>
  )
}

type ExportCardProps = {
  value: AuditExportSettings
  disabled?: boolean
  onChange: (next: AuditExportSettings) => void
  onSave: () => void
}

function ExportControlsCard({ value, disabled, onChange, onSave }: ExportCardProps) {
  const update = (patch: Partial<AuditExportSettings>) => onChange({ ...value, ...patch })
  return (
    <Card>
      <CardHeader>
        <CardTitle>Export controls</CardTitle>
        <CardDescription>Define how investigators request and approve audit log exports.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2">
          <Field label="Default export format" htmlFor="exports-format">
            <select
              id="exports-format"
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              value={value.defaultFormat}
              disabled={disabled}
              onChange={(event) => update({ defaultFormat: event.target.value as AuditExportSettings['defaultFormat'] })}
            >
              <option value="csv">CSV</option>
              <option value="json">JSON</option>
              <option value="parquet">Parquet</option>
            </select>
          </Field>
          <Field label="Max rows per export" htmlFor="exports-max">
            <Input
              id="exports-max"
              type="number"
              min={500}
              step={500}
              value={value.maxRows}
              disabled={disabled}
              onChange={(event) => update({ maxRows: Number(event.target.value) })}
            />
          </Field>
        </div>
        <label className="flex items-center gap-2 text-sm font-medium">
          <input
            type="checkbox"
            className="accent-foreground"
            checked={value.requireApproval}
            disabled={disabled}
            onChange={(event) => update({ requireApproval: event.target.checked })}
          />
          Require approval before downloads begin
        </label>
        <label className="flex items-center gap-2 text-sm font-medium">
          <input
            type="checkbox"
            className="accent-foreground"
            checked={value.watermark}
            disabled={disabled}
            onChange={(event) => update({ watermark: event.target.checked })}
          />
          Watermark exports with request metadata
        </label>
        <Field label="Approval roles" htmlFor="exports-roles" hint="Comma or newline separated role names.">
          <Textarea
            id="exports-roles"
            rows={3}
            disabled={disabled}
            value={value.approvalRoles.join('\n')}
            onChange={(event) => update({ approvalRoles: toList(event.target.value) })}
          />
        </Field>
        <Field label="Auto-expire exports (hours)" htmlFor="exports-expire">
          <Input
            id="exports-expire"
            type="number"
            min={1}
            value={value.autoExpireHours}
            disabled={disabled}
            onChange={(event) => update({ autoExpireHours: Number(event.target.value) })}
          />
        </Field>
      </CardContent>
      <CardFooter>
        <Button size="sm" onClick={onSave} disabled={disabled}>{disabled ? 'Saving…' : 'Save export controls'}</Button>
      </CardFooter>
    </Card>
  )
}

type AlertsCardProps = {
  value: AuditAlertSettings
  disabled?: boolean
  onChange: (next: AuditAlertSettings) => void
  onSave: () => void
}

function AlertRoutingCard({ value, disabled, onChange, onSave }: AlertsCardProps) {
  const update = (patch: Partial<AuditAlertSettings>) => onChange({ ...value, ...patch })

  const updateWebhook = (index: number, patch: Partial<AuditWebhookTarget>) => {
    const next = value.webhooks.map((hook, idx) => idx === index ? { ...hook, ...patch } : hook)
    update({ webhooks: next })
  }

  const addWebhook = () => {
    const next: AuditWebhookTarget = {
      id: `audit-webhook-${Date.now()}`,
      name: 'New webhook',
      url: '',
      secret: null,
      events: ['auth.lock'],
      enabled: true,
    }
    update({ webhooks: [...value.webhooks, next] })
  }

  const removeWebhook = (index: number) => {
    if (value.webhooks.length === 1) return
    update({ webhooks: value.webhooks.filter((_, idx) => idx !== index) })
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Alert routing</CardTitle>
        <CardDescription>Define which channels receive audit-critical notifications.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 md:grid-cols-2">
          {Object.entries(value.channels).map(([channel, enabled]) => (
            <label key={channel} className="flex items-center gap-2 text-sm font-medium capitalize">
              <input
                type="checkbox"
                className="accent-foreground"
                checked={Boolean(enabled)}
                disabled={disabled}
                onChange={(event) => update({ channels: { ...value.channels, [channel]: event.target.checked } })}
              />
              {channel}
            </label>
          ))}
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          {(['info', 'warning', 'critical'] as const).map((severity) => (
            <Field key={severity} label={`${severity} recipients`} htmlFor={`alerts-${severity}`}> 
              <Textarea
                id={`alerts-${severity}`}
                rows={3}
                disabled={disabled}
                value={value.severityRecipients[severity].join('\n')}
                onChange={(event) => update({ severityRecipients: { ...value.severityRecipients, [severity]: toList(event.target.value) } })}
              />
            </Field>
          ))}
        </div>

        <div className="space-y-2">
          <label className="flex items-center gap-2 text-sm font-medium">
            <input
              type="checkbox"
              className="accent-foreground"
              checked={value.notifyOn.exportRequested}
              disabled={disabled}
              onChange={(event) => update({ notifyOn: { ...value.notifyOn, exportRequested: event.target.checked } })}
            />
            Notify when exports are requested
          </label>
          <label className="flex items-center gap-2 text-sm font-medium">
            <input
              type="checkbox"
              className="accent-foreground"
              checked={value.notifyOn.exportApproved}
              disabled={disabled}
              onChange={(event) => update({ notifyOn: { ...value.notifyOn, exportApproved: event.target.checked } })}
            />
            Notify when exports are approved
          </label>
          <label className="flex items-center gap-2 text-sm font-medium">
            <input
              type="checkbox"
              className="accent-foreground"
              checked={value.notifyOn.reviewerBreach}
              disabled={disabled}
              onChange={(event) => update({ notifyOn: { ...value.notifyOn, reviewerBreach: event.target.checked } })}
            />
            Escalate when reviewer SLA is breached
          </label>
        </div>

        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-medium">Webhook targets</h4>
            <Button type="button" variant="outline" size="sm" onClick={addWebhook} disabled={disabled}>Add webhook</Button>
          </div>
          {value.webhooks.map((hook, index) => (
            <div key={hook.id} className="rounded border p-3 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">{hook.name || 'Webhook target'}</span>
                <div className="flex items-center gap-2">
                  <label className="flex items-center gap-1 text-xs uppercase tracking-wide">
                    <input
                      type="checkbox"
                      className="accent-foreground"
                      checked={hook.enabled}
                      disabled={disabled}
                      onChange={(event) => updateWebhook(index, { enabled: event.target.checked })}
                    />
                    Enabled
                  </label>
                  {value.webhooks.length > 1 ? (
                    <Button type="button" variant="ghost" size="sm" onClick={() => removeWebhook(index)} disabled={disabled}>Remove</Button>
                  ) : null}
                </div>
              </div>
              <Field label="Display name" htmlFor={`hook-name-${hook.id}`}>
                <Input
                  id={`hook-name-${hook.id}`}
                  value={hook.name}
                  disabled={disabled}
                  onChange={(event) => updateWebhook(index, { name: event.target.value })}
                />
              </Field>
              <Field label="Endpoint URL" htmlFor={`hook-url-${hook.id}`}>
                <Input
                  id={`hook-url-${hook.id}`}
                  value={hook.url}
                  disabled={disabled}
                  onChange={(event) => updateWebhook(index, { url: event.target.value })}
                />
              </Field>
              <Field label="Shared secret (optional)" htmlFor={`hook-secret-${hook.id}`}>
                <Input
                  id={`hook-secret-${hook.id}`}
                  value={hook.secret ?? ''}
                  disabled={disabled}
                  onChange={(event) => updateWebhook(index, { secret: event.target.value || null })}
                />
              </Field>
              <Field label="Event filters" htmlFor={`hook-events-${hook.id}`} hint="Comma separated events (e.g., auth.lock, admin.settings)">
                <Input
                  id={`hook-events-${hook.id}`}
                  value={hook.events.join(', ')}
                  disabled={disabled}
                  onChange={(event) => updateWebhook(index, { events: toList(event.target.value) })}
                />
              </Field>
            </div>
          ))}
        </div>
      </CardContent>
      <CardFooter>
        <Button size="sm" onClick={onSave} disabled={disabled}>{disabled ? 'Saving…' : 'Save alert routing'}</Button>
      </CardFooter>
    </Card>
  )
}

type ReviewersCardProps = {
  value: AuditReviewerSettings
  disabled?: boolean
  onChange: (next: AuditReviewerSettings) => void
  onSave: () => void
}

function ReviewersCard({ value, disabled, onChange, onSave }: ReviewersCardProps) {
  const update = (patch: Partial<AuditReviewerSettings>) => onChange({ ...value, ...patch })
  return (
    <Card>
      <CardHeader>
        <CardTitle>Reviewer roster</CardTitle>
        <CardDescription>Define who approves exports and handles escalations.</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4 md:grid-cols-2">
        <Field label="Primary reviewers" htmlFor="reviewers-primary" hint="One address per line">
          <Textarea
            id="reviewers-primary"
            rows={4}
            disabled={disabled}
            value={value.primary.join('\n')}
            onChange={(event) => update({ primary: toList(event.target.value) })}
          />
        </Field>
        <Field label="Backup reviewers" htmlFor="reviewers-backup">
          <Textarea
            id="reviewers-backup"
            rows={4}
            disabled={disabled}
            value={value.backup.join('\n')}
            onChange={(event) => update({ backup: toList(event.target.value) })}
          />
        </Field>
        <Field label="Escalation window (hours)" htmlFor="reviewers-escalation">
          <Input
            id="reviewers-escalation"
            type="number"
            min={1}
            value={value.escalationHours}
            disabled={disabled}
            onChange={(event) => update({ escalationHours: Number(event.target.value) })}
          />
        </Field>
        <Field label="Standby channel" htmlFor="reviewers-standby" hint="PagerDuty, Slack channel, or SMS alias">
          <Input
            id="reviewers-standby"
            value={value.standbyChannel}
            disabled={disabled}
            onChange={(event) => update({ standbyChannel: event.target.value })}
          />
        </Field>
      </CardContent>
      <CardFooter>
        <Button size="sm" onClick={onSave} disabled={disabled}>{disabled ? 'Saving…' : 'Save reviewer roster'}</Button>
      </CardFooter>
    </Card>
  )
}

function Field({ label, htmlFor, hint, children }: { label: string; htmlFor?: string; hint?: string; children: ReactNode }) {
  return (
    <label htmlFor={htmlFor} className="flex flex-col gap-2 text-sm font-medium">
      <span>{label}</span>
      {children}
      {hint ? <span className="text-xs text-muted-foreground">{hint}</span> : null}
    </label>
  )
}

function toList(value: string): string[] {
  return value
    .split(/\n|,/)
    .map((entry) => entry.trim())
    .filter(Boolean)
}
