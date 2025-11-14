import * as React from "react"
import { useAuth } from "@/lib/auth-context"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Separator } from "@/components/ui/separator"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import type { UserDetail, UserProfileUpdateInput } from "@/services/interfaces/types"
import { toast } from "sonner"

const PLACEHOLDER_AVATAR = "/avatars/shadcn.jpg"

type FormState = {
  name: string
  avatarUrl: string
  title: string
  department: string
  pronouns: string
  timezone: string
  locale: string
  phone: string
  bio: string
}

const EMPTY_FORM: FormState = {
  name: "",
  avatarUrl: "",
  title: "",
  department: "",
  pronouns: "",
  timezone: "",
  locale: "",
  phone: "",
  bio: "",
}

function buildInitialState(user: UserDetail | null | undefined): FormState {
  if (!user) return { ...EMPTY_FORM }
  const metadata = user.metadata && typeof user.metadata === "object" && !Array.isArray(user.metadata)
    ? (user.metadata as Record<string, unknown>)
    : {}
  const readMeta = (key: string): string => {
    const value = metadata[key]
    return typeof value === "string" ? value : ""
  }
  return {
    name: user.name ?? "",
    avatarUrl: typeof user.image === "string" ? user.image ?? "" : "",
    title: readMeta("title"),
    department: readMeta("department"),
    pronouns: readMeta("pronouns"),
    timezone: readMeta("timezone"),
    locale: readMeta("locale"),
    phone: readMeta("phone"),
    bio: readMeta("bio"),
  }
}

function normalizeInput(value: string): string | null {
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

function safeAvatarSource(form: FormState, user: UserDetail | null): string {
  if (form.avatarUrl.trim().length > 0) return form.avatarUrl.trim()
  const meta = user?.metadata && typeof user.metadata === "object" && !Array.isArray(user.metadata)
    ? (user.metadata as Record<string, unknown>)
    : null
  const metaAvatar = meta?.["avatarUrl"]
  if (typeof metaAvatar === "string" && metaAvatar.trim().length > 0) return metaAvatar.trim()
  if (user?.image && typeof user.image === "string" && user.image.trim().length > 0) return user.image.trim()
  return PLACEHOLDER_AVATAR
}

function makeInitials(user: UserDetail | null): string {
  const source = (user?.name || user?.email || "User").trim()
  if (!source) return "U"
  const parts = source.split(/\s+/)
  if (parts.length >= 2) {
    const a = parts[0]?.[0] ?? ""
    const b = parts[1]?.[0] ?? ""
    const initials = `${a}${b}`.trim()
    return initials ? initials.toUpperCase() : "U"
  }
  return source.slice(0, 2).toUpperCase() || "U"
}

function formatDate(value?: string | null): string {
  if (!value) return "—"
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date)
}

export default function ProfileSettingsPage() {
  const { user, updateProfile, initializing } = useAuth()
  const [form, setForm] = React.useState<FormState>(() => buildInitialState(user))
  const [baseline, setBaseline] = React.useState<FormState>(() => buildInitialState(user))
  const [saving, setSaving] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)

  React.useEffect(() => {
    if (!user) return
    const next = buildInitialState(user)
    setForm(next)
    setBaseline(next)
  }, [user?.id, user?.updatedAt, user?.name, user?.image, user?.metadata])

  const isDirty = React.useMemo(() => JSON.stringify(form) !== JSON.stringify(baseline), [form, baseline])

  const handleChange = React.useCallback((field: keyof FormState, value: string) => {
    setForm((prev) => ({ ...prev, [field]: value }))
  }, [])

  const handleReset = React.useCallback(() => {
    setForm(baseline)
    setError(null)
  }, [baseline])

  const handleSubmit = React.useCallback(async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!isDirty) return
    setSaving(true)
    setError(null)
    try {
      const payload: UserProfileUpdateInput = {
        name: normalizeInput(form.name),
        avatarUrl: normalizeInput(form.avatarUrl),
        title: normalizeInput(form.title),
        department: normalizeInput(form.department),
        pronouns: normalizeInput(form.pronouns),
        timezone: normalizeInput(form.timezone),
        locale: normalizeInput(form.locale),
        phone: normalizeInput(form.phone),
        bio: normalizeInput(form.bio),
      }
      const updated = await updateProfile(payload)
      const refreshed = buildInitialState(updated ?? user)
      setBaseline(refreshed)
      setForm(refreshed)
      toast.success("Profile updated")
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to update profile"
      setError(message)
      toast.error(message)
    } finally {
      setSaving(false)
    }
  }, [form, isDirty, updateProfile, user])

  if (initializing) {
    return (
      <div className="p-6">
        <div className="text-sm text-muted-foreground">Loading profile…</div>
      </div>
    )
  }

  if (!user) {
    return (
      <div className="p-6">
        <Alert variant="destructive">
          <AlertTitle>Profile unavailable</AlertTitle>
          <AlertDescription>We could not load your profile details.</AlertDescription>
        </Alert>
      </div>
    )
  }

  const avatarSrc = safeAvatarSource(form, user)
  const initials = makeInitials(user)
  const roles = Array.isArray(user.roles) ? user.roles : []
  const phoneDisplay = form.phone.trim() || "—"
  const lastUpdated = formatDate(user.updatedAt)
  const createdAt = formatDate(user.createdAt)
  const lastLoginAt = formatDate((user as any).lastLoginAt)

  return (
    <div className="p-6 space-y-6">
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">Profile</h1>
        <p className="text-sm text-muted-foreground">
          Keep your contact details and personal preferences up to date.
        </p>
      </div>

      {error ? (
        <Alert variant="destructive">
          <AlertTitle>Update failed</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <div className="grid gap-6 lg:grid-cols-[2fr,1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Profile information</CardTitle>
            <CardDescription>These details are visible to team members with access to your account.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="space-y-6" onSubmit={handleSubmit}>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="profile-name">Full name</Label>
                  <Input
                    id="profile-name"
                    value={form.name}
                    onChange={(event) => handleChange("name", event.target.value)}
                    placeholder="Ada Lovelace"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="profile-title">Title</Label>
                  <Input
                    id="profile-title"
                    value={form.title}
                    onChange={(event) => handleChange("title", event.target.value)}
                    placeholder="Director of Operations"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="profile-department">Department</Label>
                  <Input
                    id="profile-department"
                    value={form.department}
                    onChange={(event) => handleChange("department", event.target.value)}
                    placeholder="Shelter Services"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="profile-pronouns">Pronouns</Label>
                  <Input
                    id="profile-pronouns"
                    value={form.pronouns}
                    onChange={(event) => handleChange("pronouns", event.target.value)}
                    placeholder="she/her"
                  />
                </div>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="profile-timezone">Timezone</Label>
                  <Input
                    id="profile-timezone"
                    value={form.timezone}
                    onChange={(event) => handleChange("timezone", event.target.value)}
                    placeholder="America/Los_Angeles"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="profile-locale">Locale</Label>
                  <Input
                    id="profile-locale"
                    value={form.locale}
                    onChange={(event) => handleChange("locale", event.target.value)}
                    placeholder="en-US"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="profile-phone">Phone</Label>
                  <Input
                    id="profile-phone"
                    value={form.phone}
                    onChange={(event) => handleChange("phone", event.target.value)}
                    placeholder="(555) 123-4567"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="profile-avatar">Avatar image URL</Label>
                  <Input
                    id="profile-avatar"
                    value={form.avatarUrl}
                    onChange={(event) => handleChange("avatarUrl", event.target.value)}
                    placeholder="https://example.com/avatar.png"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="profile-bio">Bio</Label>
                <Textarea
                  id="profile-bio"
                  value={form.bio}
                  onChange={(event) => handleChange("bio", event.target.value)}
                  placeholder="Share a short summary to help teammates get to know you."
                  rows={5}
                />
                <p className="text-xs text-muted-foreground">Maximum 1,000 characters.</p>
              </div>

              <div className="flex flex-wrap gap-3">
                <Button type="submit" disabled={!isDirty || saving}>
                  {saving ? "Saving…" : "Save changes"}
                </Button>
                <Button type="button" variant="outline" onClick={handleReset} disabled={!isDirty || saving}>
                  Discard changes
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Preview</CardTitle>
              <CardDescription>Snapshot of how your profile appears across the workspace.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-4">
                <Avatar className="h-16 w-16">
                  <AvatarImage src={avatarSrc} alt={user.name || user.email || "User avatar"} />
                  <AvatarFallback>{initials}</AvatarFallback>
                </Avatar>
                <div className="space-y-1">
                  <div className="text-lg font-semibold leading-tight">{form.name || user.name || user.email}</div>
                  <div className="text-sm text-muted-foreground">
                    {[form.title, form.department].filter(Boolean).join(" • ") || "Add a title"}
                  </div>
                  <div className="text-xs text-muted-foreground">Last updated {lastUpdated}</div>
                </div>
              </div>
              <Separator />
              <div className="space-y-3 text-sm">
                <div>
                  <div className="text-muted-foreground">Email</div>
                  <div className="font-medium">{user.email}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Phone</div>
                  <div className="font-medium">{phoneDisplay}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Timezone</div>
                  <div className="font-medium">{form.timezone.trim() || "—"}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Locale</div>
                  <div className="font-medium">{form.locale.trim() || "—"}</div>
                </div>
              </div>
              <Separator />
              <div className="space-y-2">
                <div className="text-muted-foreground text-sm">Roles</div>
                {roles.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {roles.map((role) => (
                      <Badge key={role} variant="secondary">{role}</Badge>
                    ))}
                  </div>
                ) : (
                  <div className="text-sm text-muted-foreground">No roles assigned</div>
                )}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Account activity</CardTitle>
              <CardDescription>Timestamps reflect your current session timezone.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div>
                <div className="text-muted-foreground">Member since</div>
                <div className="font-medium">{createdAt}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Last login</div>
                <div className="font-medium">{lastLoginAt}</div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
