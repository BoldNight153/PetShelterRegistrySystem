import { useCallback, useEffect, useMemo, useState } from 'react'
import { useServices } from '@/services/hooks'
import type { AuditTimelineEntry } from '@/services/interfaces/types'
import type { AuditQuery } from '@/services/interfaces/audit.interface'
import type { Page } from '@/services/interfaces/types'

const EMPTY_PAGE: Page<AuditTimelineEntry> = { items: [], total: 0, page: 1, pageSize: 25 }

export function useActivityHistory(filters: AuditQuery) {
  const services = useServices()
  const audit = services.audit
  const [data, setData] = useState<Page<AuditTimelineEntry>>(EMPTY_PAGE)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const normalizedFilters = useMemo(() => ({
    ...filters,
  }), [filters])

  const fetchLogs = useCallback(async () => {
    if (!audit?.list) {
      setError('Audit service unavailable')
      return
    }
    setLoading(true)
    setError(null)
    try {
      const result = await audit.list(normalizedFilters)
      setData(result)
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to load activity'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }, [audit, normalizedFilters])

  useEffect(() => {
    fetchLogs()
  }, [fetchLogs])

  return { data, loading, error, refresh: fetchLogs }
}
