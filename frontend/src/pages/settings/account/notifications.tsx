import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  AlarmClockCheck,
  AlertTriangle,
  Bell,
  BellRing,
  ListChecks,
  Mail,
  MessageSquare,
  ShieldCheck,
  Smartphone,
  Wifi,
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { toast } from 'sonner'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  DEFAULT_NOTIFICATION_SETTINGS,
  type NotificationChannel,
  type NotificationDevice,
  type NotificationDigestFrequency,
  type NotificationSettings,
  type NotificationSettingsInput,
  type NotificationTopicPreference,
  type NotificationTopicCategory,
} from '@/types/notifications'
import { useNotificationSettings, useUpdateNotificationSettings, useRegisterNotificationDevice } from '@/services/hooks/notifications'
import { buildNotificationRegistrationPayload, supportsPushNotifications } from '@/lib/notifications-device'
import { cn } from '@/lib/utils'

const CHANNEL_METADATA: Record<NotificationChannel, { label: string; icon: React.ComponentType<{ className?: string }> }> = {
  email: { label: 'Email', icon: Mail },
  sms: { label: 'SMS', icon: MessageSquare },
  push: { label: 'Push', icon: BellRing },
  in_app: { label: 'In-app', icon: Bell },
}

const CATEGORY_LABELS: Record<NotificationTopicCategory, string> = {
  account: 'Account',
  animals: 'Animal care',
  operations: 'Operations',
  security: 'Security',
  system: 'System',
}

const HOUR_OPTIONS = Array.from({ length: 24 }, (_, hour) => ({ value: hour, label: formatHour(hour) }))
const DIGEST_FREQUENCIES: NotificationDigestFrequency[] = ['daily', 'weekly']

type SectionKey = 'channels' | 'topics' | 'digests' | 'quietHours' | 'escalations' | 'devices'

const INITIAL_SECTION_STATE: Record<SectionKey, boolean> = {
  channels: false,
  topics: false,
  digests: false,
  quietHours: false,
  escalations: false,
  devices: false,
}

export default function NotificationsSettingsPage() {
  const settingsQuery = useNotificationSettings()
  const updateSettings = useUpdateNotificationSettings()
  const registerDevice = useRegisterNotificationDevice()

  const [draft, setDraft] = useState<NotificationSettings>(() => cloneSettings(DEFAULT_NOTIFICATION_SETTINGS))
  const [dirty, setDirty] = useState<Record<SectionKey, boolean>>(INITIAL_SECTION_STATE)
  const [saving, setSaving] = useState<Record<SectionKey, boolean>>(INITIAL_SECTION_STATE)
  const [registeringDevice, setRegisteringDevice] = useState(false)
  const canRegisterDevice = supportsPushNotifications()

  const handleDeviceRegistration = async () => {
    if (!canRegisterDevice) {
      toast.error('Push registration is not available in this browser')
      return
    }
    try {
      setRegisteringDevice(true)
      const payload = await buildNotificationRegistrationPayload()
      await registerDevice.mutateAsync(payload)
      await settingsQuery.refetch()
      toast.success('Device registered for push alerts')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to register this device'
      toast.error(message)
    } finally {
      setRegisteringDevice(false)
    }
  }

  useEffect(() => {
    if (!settingsQuery.data) return
    setDraft(cloneSettings(settingsQuery.data))
    setDirty(INITIAL_SECTION_STATE)
  }, [settingsQuery.data])

  const isLoading = settingsQuery.isLoading && !settingsQuery.data
  const error = settingsQuery.error as Error | null

  const summary = useMemo(() => buildSummary(draft), [draft])

  const handleSave = async (section: SectionKey, payload: NotificationSettingsInput, successMessage: string) => {
    try {
      setSaving((prev) => ({ ...prev, [section]: true }))
      const next = await updateSettings.mutateAsync(payload)
      setDraft(cloneSettings(next))
      setDirty((prev) => ({ ...prev, [section]: false }))
      toast.success(successMessage)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to update notifications'
      toast.error(message)
    } finally {
      setSaving((prev) => ({ ...prev, [section]: false }))
    }
  }

  const toggleDefaultChannel = (channel: NotificationChannel) => {
    setDraft((prev) => {
      const hasChannel = prev.defaultChannels.includes(channel)
      if (hasChannel && prev.defaultChannels.length === 1) {
        toast.error('At least one default channel is required')
        return prev
      }
      const nextChannels = hasChannel
        ? prev.defaultChannels.filter((entry) => entry !== channel)
        : [...prev.defaultChannels, channel]
      setDirty((state) => ({ ...state, channels: true }))
      return { ...prev, defaultChannels: nextChannels }
    })
  }

  const updateTopic = (topicId: string, patch: Partial<NotificationTopicPreference>) => {
    setDraft((prev) => {
      const nextTopics = prev.topics.map((topic) => (topic.id === topicId ? { ...topic, ...patch } : topic))
      return { ...prev, topics: nextTopics }
    })
    setDirty((state) => ({ ...state, topics: true }))
  }

  const toggleTopicChannel = (topicId: string, channel: NotificationChannel) => {
    setDraft((prev) => {
      const nextTopics = prev.topics.map((topic) => {
        if (topic.id !== topicId) return topic
        const hasChannel = topic.channels.includes(channel)
        const nextChannels = hasChannel
          ? topic.channels.filter((entry) => entry !== channel)
          : [...topic.channels, channel]
        return { ...topic, channels: nextChannels }
      })
      return { ...prev, topics: nextTopics }
    })
    setDirty((state) => ({ ...state, topics: true }))
  }

  const updateDigest = (patch: Partial<NotificationSettings['digests']>) => {
    setDraft((prev) => ({ ...prev, digests: { ...prev.digests, ...patch } }))
    setDirty((state) => ({ ...state, digests: true }))
  }

  const updateQuietHours = (patch: Partial<NotificationSettings['quietHours']>) => {
    setDraft((prev) => ({ ...prev, quietHours: { ...prev.quietHours, ...patch } }))
    setDirty((state) => ({ ...state, quietHours: true }))
  }

  const updateEscalations = (patch: Partial<NotificationSettings['criticalEscalations']>) => {
    setDraft((prev) => ({ ...prev, criticalEscalations: { ...prev.criticalEscalations, ...patch } }))
    setDirty((state) => ({ ...state, escalations: true }))
  }

  const toggleDevice = (deviceId: string) => {
    setDraft((prev) => {
      const nextDevices = prev.devices.map((device) =>
        device.id === deviceId ? { ...device, enabled: !device.enabled } : device,
      )
      return { ...prev, devices: nextDevices }
    })
    setDirty((state) => ({ ...state, devices: true }))
  }

  if (isLoading) {
    return <NotificationsSkeleton />
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <Bell className="h-6 w-6 text-primary" />
        <div>
          <h1 className="text-2xl font-semibold">Notifications & alerts</h1>
          <p className="text-muted-foreground">
            Fine-tune default channels, topic-level delivery, digest cadence, quiet hours, and escalation targets so teams get signal—not noise.
          </p>
        </div>
      </div>

      <Alert variant="secondary">
        <ShieldCheck className="h-4 w-4" />
        <AlertTitle>Security alerts now live here</AlertTitle>
        <AlertDescription>
          We migrated the personal security alert preferences from the security page so every delivery control lives in a single workspace.
          Manage break-glass settings from the <Link to="/settings/account/security#alerts" className="underline underline-offset-4">security tab</Link> if you still need the legacy view.
        </AlertDescription>
      </Alert>

      {error ? (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Unable to load notification settings</AlertTitle>
          <AlertDescription className="flex flex-wrap items-center gap-3">
            {error.message}
            <Button variant="outline" size="sm" onClick={() => settingsQuery.refetch()}>
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      ) : null}

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <ListChecks className="h-4 w-4 text-primary" />
              Topic coverage
            </CardTitle>
            <CardDescription>Active topics vs. total available bundles.</CardDescription>
          </CardHeader>
          <CardContent className="flex items-end justify-between">
            <div>
              <p className="text-3xl font-semibold">{summary.activeTopics}</p>
              <p className="text-sm text-muted-foreground">active of {summary.totalTopics}</p>
            </div>
            <Badge variant="outline">{summary.criticalTopics} critical</Badge>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <AlarmClockCheck className="h-4 w-4 text-primary" />
              Digest cadence
            </CardTitle>
            <CardDescription>Morning recaps keep everyone in sync.</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-3xl font-semibold">{summary.digestLabel}</p>
            <p className="text-sm text-muted-foreground">{summary.digestDescription}</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Wifi className="h-4 w-4 text-primary" />
              Quiet hours & escalations
            </CardTitle>
            <CardDescription>Prevent pager fatigue, escalate what matters.</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-3xl font-semibold">{summary.quietHoursLabel}</p>
            <p className="text-sm text-muted-foreground">{summary.escalationSummary}</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <SectionHeader
          icon={BellRing}
          title="Default delivery channels"
          description="Applied whenever a topic does not override the channel mix."
          dirty={dirty.channels}
        />
        <CardContent className="flex flex-wrap gap-3">
          {Object.entries(CHANNEL_METADATA).map(([channel, meta]) => {
            const Icon = meta.icon
            const active = draft.defaultChannels.includes(channel as NotificationChannel)
            return (
              <ChannelToggle
                key={channel}
                active={active}
                label={meta.label}
                icon={Icon}
                onClick={() => toggleDefaultChannel(channel as NotificationChannel)}
                ariaLabel={`Toggle default channel ${meta.label}`}
              />
            )
          })}
        </CardContent>
        <CardFooter className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
          <p className="text-sm text-muted-foreground">Requires at least one channel so urgent alerts always have a route.</p>
          <Button
            type="button"
            disabled={!dirty.channels || saving.channels}
            onClick={() => handleSave('channels', { defaultChannels: draft.defaultChannels }, 'Channel defaults saved')}
          >
            {saving.channels ? 'Saving…' : 'Save channel defaults'}
          </Button>
        </CardFooter>
      </Card>

      <Card>
        <SectionHeader
          icon={ListChecks}
          title="Topic-level delivery"
          description="Tune each notification bundle with per-channel overrides."
          dirty={dirty.topics}
        />
        <CardContent className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Topic</TableHead>
                <TableHead>Category</TableHead>
                <TableHead>Channels</TableHead>
                <TableHead className="text-right">Delivery</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {draft.topics.map((topic) => (
                <TableRow key={topic.id} className={cn(topic.critical && 'bg-destructive/5')}> 
                  <TableCell className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{topic.label}</span>
                      {topic.critical ? <Badge variant="destructive">Critical</Badge> : null}
                    </div>
                    {topic.description ? (
                      <p className="text-xs text-muted-foreground">{topic.description}</p>
                    ) : null}
                    {topic.muteUntil ? (
                      <p className="text-[11px] text-muted-foreground">
                        Muted until {formatDistanceToNow(new Date(topic.muteUntil), { addSuffix: true })}
                      </p>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{CATEGORY_LABELS[topic.category]}</Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(CHANNEL_METADATA).map(([channel, meta]) => {
                        const Icon = meta.icon
                        const active = topic.channels.includes(channel as NotificationChannel)
                        return (
                          <ChannelToggle
                            key={`${topic.id}-${channel}`}
                            size="sm"
                            active={active}
                            label={meta.label}
                            icon={Icon}
                            onClick={() => toggleTopicChannel(topic.id, channel as NotificationChannel)}
                            ariaLabel={`Toggle ${meta.label} for ${topic.label}`}
                          />
                        )
                      })}
                    </div>
                  </TableCell>
                  <TableCell className="flex items-center justify-end gap-3">
                    <Switch checked={topic.enabled} onCheckedChange={(value) => updateTopic(topic.id, { enabled: value })} />
                    <span className="text-sm">{topic.enabled ? 'On' : 'Paused'}</span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
        <CardFooter className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
          <p className="text-sm text-muted-foreground">Channel overrides win over defaults, so you can keep critical workflows high-signal.</p>
          <Button
            type="button"
            disabled={!dirty.topics || saving.topics}
            onClick={() => handleSave('topics', { topics: draft.topics }, 'Topic overrides saved')}
          >
            {saving.topics ? 'Saving…' : 'Save topic overrides'}
          </Button>
        </CardFooter>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <SectionHeader
            icon={Activity}
            title="Digest scheduling"
            description="Daily or weekly summaries with timezone-aware delivery."
            dirty={dirty.digests}
          />
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <Label htmlFor="digest-enabled">Digest enabled</Label>
              <Switch
                id="digest-enabled"
                checked={draft.digests.enabled}
                onCheckedChange={(checked) => updateDigest({ enabled: checked })}
              />
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label>Frequency</Label>
                <Select
                  value={draft.digests.frequency}
                  onValueChange={(value) => updateDigest({ frequency: value as NotificationDigestFrequency })}
                >
                  <SelectTrigger aria-label="Digest frequency">
                    <SelectValue placeholder="Choose" />
                  </SelectTrigger>
                  <SelectContent>
                    {DIGEST_FREQUENCIES.map((freq) => (
                      <SelectItem key={freq} value={freq}>
                        {freq === 'daily' ? 'Daily recap' : 'Weekly briefing'}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Send hour</Label>
                <Select
                  value={String(draft.digests.sendHourLocal)}
                  onValueChange={(value) => updateDigest({ sendHourLocal: Number(value) })}
                >
                  <SelectTrigger aria-label="Digest hour">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {HOUR_OPTIONS.map((option) => (
                      <SelectItem key={option.value} value={String(option.value)}>
                        {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="digest-timezone">Timezone</Label>
              <Input
                id="digest-timezone"
                value={draft.digests.timezone ?? ''}
                onChange={(event) => updateDigest({ timezone: event.target.value || null })}
                placeholder="America/Los_Angeles"
              />
            </div>
            <div className="flex items-center justify-between">
              <Label htmlFor="digest-summary">Include summary</Label>
              <Switch
                id="digest-summary"
                checked={draft.digests.includeSummary}
                onCheckedChange={(checked) => updateDigest({ includeSummary: checked })}
              />
            </div>
          </CardContent>
          <CardFooter className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
            <p className="text-sm text-muted-foreground">Readers still receive real-time alerts—digests just bundle a recap.</p>
            <Button
              type="button"
              disabled={!dirty.digests || saving.digests}
              onClick={() => handleSave('digests', { digests: draft.digests }, 'Digest schedule saved')}
            >
              {saving.digests ? 'Saving…' : 'Save digest schedule'}
            </Button>
          </CardFooter>
        </Card>

        <Card>
          <SectionHeader
            icon={AlarmClockCheck}
            title="Quiet hours"
            description="Mute non-critical traffic overnight while allowing overrides."
            dirty={dirty.quietHours}
          />
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <Label htmlFor="quiet-hours-enabled">Quiet hours enabled</Label>
              <Switch
                id="quiet-hours-enabled"
                checked={draft.quietHours.enabled}
                onCheckedChange={(checked) => updateQuietHours({ enabled: checked })}
              />
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label>Starts</Label>
                <Select
                  value={String(draft.quietHours.startHour)}
                  onValueChange={(value) => updateQuietHours({ startHour: Number(value) })}
                >
                  <SelectTrigger aria-label="Quiet hours start">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {HOUR_OPTIONS.map((option) => (
                      <SelectItem key={option.value} value={String(option.value)}>
                        {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Ends</Label>
                <Select
                  value={String(draft.quietHours.endHour)}
                  onValueChange={(value) => updateQuietHours({ endHour: Number(value) })}
                >
                  <SelectTrigger aria-label="Quiet hours end">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {HOUR_OPTIONS.map((option) => (
                      <SelectItem key={option.value} value={String(option.value)}>
                        {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="quiet-timezone">Timezone</Label>
              <Input
                id="quiet-timezone"
                value={draft.quietHours.timezone ?? ''}
                onChange={(event) => updateQuietHours({ timezone: event.target.value || null })}
                placeholder="America/Chicago"
              />
            </div>
          </CardContent>
          <CardFooter className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
            <p className="text-sm text-muted-foreground">Critical topics ignore quiet hours so life-safety alerts still escalate.</p>
            <Button
              type="button"
              disabled={!dirty.quietHours || saving.quietHours}
              onClick={() => handleSave('quietHours', { quietHours: draft.quietHours }, 'Quiet hours saved')}
            >
              {saving.quietHours ? 'Saving…' : 'Save quiet hours'}
            </Button>
          </CardFooter>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <SectionHeader
            icon={ShieldCheck}
            title="Critical escalations"
            description="Define fallback channels for security + life-safety alerts."
            dirty={dirty.escalations}
          />
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <Label htmlFor="sms-fallback">SMS fallback</Label>
              <Switch
                id="sms-fallback"
                checked={draft.criticalEscalations.smsFallback}
                onCheckedChange={(checked) => updateEscalations({ smsFallback: checked })}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="backup-email">Backup email</Label>
              <Input
                id="backup-email"
                type="email"
                placeholder="incident@organization.org"
                value={draft.criticalEscalations.backupEmail ?? ''}
                onChange={(event) => updateEscalations({ backupEmail: event.target.value || null })}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="pager-duty">PagerDuty webhook</Label>
              <Input
                id="pager-duty"
                type="url"
                placeholder="https://events.pagerduty.com/v2/enqueue..."
                value={draft.criticalEscalations.pagerDutyWebhook ?? ''}
                onChange={(event) => updateEscalations({ pagerDutyWebhook: event.target.value || null })}
              />
            </div>
          </CardContent>
          <CardFooter className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
            <p className="text-sm text-muted-foreground">Escalations mirror to security alerts automatically.</p>
            <Button
              type="button"
              disabled={!dirty.escalations || saving.escalations}
              onClick={() => handleSave('escalations', { criticalEscalations: draft.criticalEscalations }, 'Escalation targets saved')}
            >
              {saving.escalations ? 'Saving…' : 'Save escalations'}
            </Button>
          </CardFooter>
        </Card>

        <Card>
          <SectionHeader
            icon={Smartphone}
            title="Trusted devices"
            description="Control which devices are eligible for push + in-app delivery."
            dirty={dirty.devices}
          />
          <CardContent className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-sm text-muted-foreground">Register this browser or device to start receiving push alerts.</p>
              {canRegisterDevice ? (
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleDeviceRegistration}
                  disabled={registeringDevice || settingsQuery.isFetching}
                >
                  {registeringDevice ? 'Registering…' : 'Register this device'}
                </Button>
              ) : (
                <Badge variant="outline">Push unsupported</Badge>
              )}
            </div>
            {draft.devices.length === 0 ? (
              <Alert>
                <AlertDescription>No devices registered yet. We’ll populate this list as clients opt-in.</AlertDescription>
              </Alert>
            ) : (
              <div className="space-y-3">
                {draft.devices.map((device) => (
                  <DeviceRow key={device.id} device={device} onToggle={() => toggleDevice(device.id)} />
                ))}
              </div>
            )}
          </CardContent>
          <CardFooter className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
            <p className="text-sm text-muted-foreground">Disable a device to pause push + in-app delivery until it checks in again.</p>
            <Button
              type="button"
              disabled={!dirty.devices || saving.devices}
              onClick={() => handleSave('devices', { devices: draft.devices }, 'Device preferences saved')}
            >
              {saving.devices ? 'Saving…' : 'Save device preferences'}
            </Button>
          </CardFooter>
        </Card>
      </div>
    </div>
  )
}

function NotificationsSkeleton() {
  return (
    <div className="space-y-6">
      <Skeleton className="h-8 w-72" />
      <div className="grid gap-4 md:grid-cols-3">
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
      </div>
      <Skeleton className="h-64" />
      <Skeleton className="h-96" />
      <div className="grid gap-6 md:grid-cols-2">
        <Skeleton className="h-80" />
        <Skeleton className="h-80" />
      </div>
    </div>
  )
}

function SectionHeader({
  icon: Icon,
  title,
  description,
  dirty,
}: {
  icon: React.ComponentType<{ className?: string }>
  title: string
  description: string
  dirty?: boolean
}) {
  return (
    <CardHeader className="flex flex-wrap items-center justify-between gap-3">
      <div>
        <CardTitle className="flex items-center gap-2 text-base">
          <Icon className="h-4 w-4 text-primary" />
          {title}
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </div>
      {dirty ? <Badge variant="secondary">Unsaved changes</Badge> : null}
    </CardHeader>
  )
}

function ChannelToggle({
  active,
  icon: Icon,
  label,
  onClick,
  size = 'default',
  ariaLabel,
}: {
  active: boolean
  icon: React.ComponentType<{ className?: string }>
  label: string
  onClick: () => void
  size?: 'sm' | 'default'
  ariaLabel?: string
}) {
  return (
    <Button
      type="button"
      variant={active ? 'default' : 'outline'}
      size={size === 'sm' ? 'sm' : 'default'}
      className={cn('gap-2', size === 'sm' && 'text-xs')}
      onClick={onClick}
      aria-pressed={active}
      aria-label={ariaLabel ?? label}
    >
      <Icon className="h-4 w-4" />
      {label}
    </Button>
  )
}

function DeviceRow({ device, onToggle }: { device: NotificationDevice; onToggle: () => void }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border p-3">
      <div>
        <p className="font-medium">{device.label}</p>
        <p className="text-xs text-muted-foreground">
          {device.platform.toUpperCase()} • {device.lastUsedAt ? formatDistanceToNow(new Date(device.lastUsedAt), { addSuffix: true }) : 'Never used'}
        </p>
      </div>
      <div className="flex items-center gap-2">
        <Switch
          checked={device.enabled}
          onCheckedChange={onToggle}
          aria-label={`Toggle ${device.label}`}
          data-testid={`device-toggle-${device.id}`}
        />
        <span className="text-sm">{device.enabled ? 'Enabled' : 'Paused'}</span>
      </div>
    </div>
  )
}

function cloneSettings(value: NotificationSettings | undefined): NotificationSettings {
  return JSON.parse(JSON.stringify(value ?? DEFAULT_NOTIFICATION_SETTINGS)) as NotificationSettings
}

function formatHour(hour: number): string {
  const normalized = ((hour % 24) + 24) % 24
  const base = normalized % 12 || 12
  const suffix = normalized >= 12 ? 'PM' : 'AM'
  return `${base}:00 ${suffix}`
}

function buildSummary(settings: NotificationSettings) {
  const activeTopics = settings.topics.filter((topic) => topic.enabled).length
  const criticalTopics = settings.topics.filter((topic) => topic.critical).length
  const digestLabel = settings.digests.enabled ? settings.digests.frequency === 'daily' ? 'Daily' : 'Weekly' : 'Disabled'
  const digestDescription = settings.digests.enabled
    ? `${formatHour(settings.digests.sendHourLocal)} • ${settings.digests.timezone ?? 'UTC'}`
    : 'Recipients only receive real-time alerts'
  const quietHoursLabel = settings.quietHours.enabled
    ? `${formatHour(settings.quietHours.startHour)} – ${formatHour(settings.quietHours.endHour)}`
    : 'Off'
  const escalationSummary = settings.criticalEscalations.smsFallback
    ? 'SMS fallback enabled'
    : settings.criticalEscalations.backupEmail
      ? 'Email escalation only'
      : 'Escalations disabled'

  return {
    activeTopics,
    criticalTopics,
    totalTopics: settings.topics.length,
    digestLabel,
    digestDescription,
    quietHoursLabel,
    escalationSummary,
  }
}
