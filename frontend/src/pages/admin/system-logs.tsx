import { ShieldCheck } from 'lucide-react'

import { AuditActivityConsole, type AuditFocusOption } from '@/components/audit/audit-activity-console'

const SYSTEM_FOCUS_PRESETS: AuditFocusOption[] = [
  { id: 'platform', label: 'Platform signals', description: 'Kernel alerts, failovers, and noisy dependency resets.', filters: { action: 'platform.' } },
  { id: 'automation', label: 'Automation jobs', description: 'CRON invocations, rate-limit resets, and retention sweeps.', filters: { action: 'jobs.' } },
  { id: 'integrity', label: 'Integrity controls', description: 'Tamper detection, checksum mismatches, KV divergence.', filters: { action: 'integrity.' } },
  { id: 'api', label: 'API ingestion', description: 'Webhook ingestion failures and downstream retries.', filters: { action: 'integrations.' } },
]

const SYSTEM_RETENTION_NOTES = [
  'Live search spans the last 48h of infrastructure automation signals.',
  'Cold copies persist for 400 days and feed the operations rehearsal program.',
  'Exports require system_admin + ops.reviewer roles and log an audit trail.',
  'Retention rules pause automatically while an incident is declared.',
]

export default function SystemLogsPage() {
  return (
    <AuditActivityConsole
      icon={ShieldCheck}
      title="System Logs"
      description="Focus on infrastructure automation streams shared with the audit workspace."
      badgeLabel="Platform observability"
      focusOptions={SYSTEM_FOCUS_PRESETS}
      retentionHighlights={SYSTEM_RETENTION_NOTES}
      presetTitle="Investigative scopes"
      presetDescription="Align filters with backend stream categories pulled from the ops runbook."
      filtersTitle="Deep filter controls"
      filtersDescription="Drill into service owners, automation IDs, or origin hosts without leaving this view."
      timelineTitle="System log timeline"
      timelineDescription="Chronological feed of privileged platform signals replicated from /admin/audit."
    />
  )
}
