import { Shield } from 'lucide-react'

import { AuditActivityConsole } from '@/components/audit/audit-activity-console'

export default function AuditLogsPage() {
  return (
    <AuditActivityConsole
      icon={Shield}
      title="Audit Logs"
      description="Investigate privileged actions and sign-in events across the platform."
      badgeLabel="Security & Access"
    />
  )
}
