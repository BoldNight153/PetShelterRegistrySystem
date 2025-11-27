import * as React from "react"
import { KeyRound, Layers, ShieldAlert, ShieldCheck, Share2, X } from "lucide-react"
import type { LucideIcon } from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { cn } from "@/lib/utils"
import { DEFAULT_ENABLED_AUTHENTICATORS } from "@/lib/authenticator-catalog"
import { useAuth } from "@/lib/auth-context"
import { filterNavigationTree, resolveIcon } from "@/lib/navigation-map"
import {
	useAdminSettings,
	useSaveAdminSettings,
	useAuthenticatorCatalog,
	useCreateAuthenticator,
	useUpdateAuthenticator,
	useArchiveAuthenticator,
	useRestoreAuthenticator,
} from "@/services/hooks/admin"
import { useNavigationMenu } from "@/services/hooks/navigation"
import type {
	AdminAuthenticatorCatalogRecord,
	AuthenticatorFactorType,
	CreateAdminAuthenticatorInput,
	UpdateAdminAuthenticatorInput,
} from "@/services/interfaces/admin.interface"
import type { JsonValue } from "@/services/interfaces/types"
import type { NavigationMenu, NavigationMenuItem } from "@/services/interfaces/navigation.interface"
import { Link, useLocation, useNavigate, useOutlet, useSearchParams } from "react-router-dom"

type SettingsCategory = "general" | "monitoring" | "auth" | "docs" | "security"

type SectionNavItem = {
	id: string
	title: string
	category?: SettingsCategory
	route?: string
	icon?: LucideIcon
	comingSoon: boolean
	parentTitle: string
}

type SectionGroup = {
	id: string
	title: string
	items: SectionNavItem[]
}

type GeneralState = {
	appName: string
	supportEmail: string
}

type MonitoringState = {
	chartsRefreshSec: number
	retentionDays: number
}

type AuthMfaPolicy = "optional" | "recommended" | "required"

type AuthState = {
	mode: "session" | "jwt"
	google: boolean
	github: boolean
	enforceMfa: AuthMfaPolicy
	authenticators: string[]
}

type DocsState = {
	showPublicDocsLink: boolean
}

type SecurityState = {
	sessionMaxAgeMin: number
	requireEmailVerification: boolean
	loginIpWindowSec: number
	loginIpLimit: number
	loginLockWindowSec: number
	loginLockThreshold: number
	loginLockDurationMin: number
	passwordHistoryLimit: number
}

type AuthenticatorDraft = {
	id: string
	label: string
	description: string
	factorType: AuthenticatorFactorType
	issuer: string
	helper: string
	docsUrl: string
	tags: string
	metadata: string
	sortOrder: string
}

type CatalogDialogState = { mode: "create" | "edit"; entry?: AdminAuthenticatorCatalogRecord | null } | null
type CatalogDisplayEntry = AdminAuthenticatorCatalogRecord & { _missing?: boolean }

type BadgeVariant = React.ComponentProps<typeof Badge>["variant"]

type AuthRunStateContext = {
	state: AuthState
	activeOauthCount: number
	authenticatorCount: number
	missingAuthenticatorCount: number
}

type AuthRunStateMeta = {
	id: string
	title: string
	icon: LucideIcon
	compute(context: AuthRunStateContext): { label: string; helper: string; variant: BadgeVariant }
}

const FACTOR_TYPE_OPTIONS: Array<{ value: AuthenticatorFactorType; label: string }> = [
	{ value: "TOTP", label: "Authenticator app (TOTP)" },
	{ value: "SMS", label: "SMS code" },
	{ value: "PUSH", label: "Push notification" },
	{ value: "HARDWARE_KEY", label: "Hardware key" },
	{ value: "BACKUP_CODES", label: "Backup codes" },
]

const LOGIN_MODE_OPTIONS: Array<{ value: AuthState["mode"]; title: string; description: string; badge: string }> = [
	{
		value: "session",
		title: "Session cookies",
		description: "Issue HttpOnly refresh/access cookies for browser-first workflows.",
		badge: "Recommended",
	},
	{
		value: "jwt",
		title: "JWT access tokens",
		description: "Return stateless tokens for SPAs, CLIs, or partner API integrations.",
		badge: "Advanced",
	},
]

const MFA_POLICY_COPY: Record<AuthMfaPolicy, { label: string; helper: string }> = {
	optional: {
		label: "Optional",
		helper: "Let users opt in at their own pace while showing contextual reminders.",
	},
	recommended: {
		label: "Recommended",
		helper: "Nudge unenrolled accounts every month but allow temporary skips.",
	},
	required: {
		label: "Required",
		helper: "Block access until at least one MFA factor is active for the account.",
	},
}

const OAUTH_PROVIDERS: Array<{ key: keyof Pick<AuthState, "google" | "github">; label: string; description: string }> = [
	{
		key: "google",
		label: "Google",
		description: "Allow workspace members to sign in with Google Workspace or Gmail accounts.",
	},
	{
		key: "github",
		label: "GitHub",
		description: "Enable login for maintainers that already use GitHub SSO.",
	},
]

const AUTH_ID_PATTERN = /^[a-z0-9_-]+$/i

const AUTH_RUN_STATES: AuthRunStateMeta[] = [
	{
		id: "mode",
		title: "Login issuance",
		icon: ShieldCheck,
		compute: ({ state }) => {
			return state.mode === "session"
				? {
					label: "Session cookies",
					helper: "Refresh and access tokens are issued as HttpOnly cookies.",
					variant: "secondary",
				}
				: {
					label: "JWT tokens",
					helper: "Stateless tokens for SPAs, CLIs, and partner APIs.",
					variant: "default",
				}
		},
	},
	{
		id: "mfa",
		title: "MFA enforcement",
		icon: KeyRound,
		compute: ({ state }) => {
			const policy = MFA_POLICY_COPY[state.enforceMfa]
			const variant: BadgeVariant = state.enforceMfa === "required"
				? "secondary"
				: state.enforceMfa === "recommended"
					? "default"
					: "destructive"
			return {
				label: policy.label,
				helper: policy.helper,
				variant,
			}
		},
	},
	{
		id: "oauth",
		title: "OAuth providers",
		icon: Share2,
		compute: ({ activeOauthCount }) => {
			const label = activeOauthCount
				? `${activeOauthCount} provider${activeOauthCount === 1 ? "" : "s"} enabled`
				: "No providers enabled"
			return {
				label,
				helper: activeOauthCount
					? "Admins can use SSO for dashboard access."
					: "Connect a provider to allow single sign-on.",
				variant: activeOauthCount ? "secondary" : "outline",
			}
		},
	},
	{
		id: "catalog",
		title: "Authenticator coverage",
		icon: Layers,
		compute: ({ authenticatorCount, missingAuthenticatorCount }) => {
			if (!authenticatorCount) {
				return {
					label: "No authenticators enabled",
					helper: "Users cannot enroll MFA factors yet.",
					variant: "destructive",
				}
			}
			if (missingAuthenticatorCount > 0) {
				return {
					label: `${authenticatorCount} factor${authenticatorCount === 1 ? "" : "s"} allowed`,
					helper: `${missingAuthenticatorCount} need catalog cleanup.`,
					variant: "default",
				}
			}
			return {
				label: `${authenticatorCount} factor${authenticatorCount === 1 ? "" : "s"} allowed`,
				helper: "Curated factors appear in the Security workspace.",
				variant: "secondary",
			}
		},
	},
]

function coerceAuthenticatorSelection(value: unknown): string[] {
	if (!Array.isArray(value)) return [...DEFAULT_ENABLED_AUTHENTICATORS]
	const deduped: string[] = []
	const seen = new Set<string>()
	for (const entry of value) {
		if (typeof entry !== "string") continue
		const trimmed = entry.trim()
		if (!trimmed || seen.has(trimmed)) continue
		seen.add(trimmed)
		deduped.push(trimmed)
	}
	return deduped
}

function createEmptyCatalogDraft(): AuthenticatorDraft {
	return {
		id: "",
		label: "",
		description: "",
		factorType: "TOTP",
		issuer: "",
		helper: "",
		docsUrl: "",
		tags: "",
		metadata: "",
		sortOrder: "0",
	}
}

function draftFromCatalogEntry(entry: AdminAuthenticatorCatalogRecord): AuthenticatorDraft {
	return {
		id: entry.id,
		label: entry.label,
		description: entry.description ?? "",
		factorType: entry.factorType,
		issuer: entry.issuer ?? "",
		helper: entry.helper ?? "",
		docsUrl: entry.docsUrl ?? "",
		tags: entry.tags?.join(", ") ?? "",
		metadata: entry.metadata ? JSON.stringify(entry.metadata, null, 2) : "",
		sortOrder: typeof entry.sortOrder === "number" ? String(entry.sortOrder) : "0",
	}
}

function buildMissingCatalogEntry(id: string): CatalogDisplayEntry {
	return {
		id,
		label: id,
		description: "This authenticator no longer exists in the catalog.",
		factorType: "TOTP",
		issuer: null,
		helper: null,
		docsUrl: null,
		tags: null,
		metadata: null,
		sortOrder: null,
		isArchived: true,
		createdAt: null,
		updatedAt: null,
		archivedAt: null,
		archivedBy: null,
		_missing: true,
	}
}

function parseTagsInput(value: string): string[] | null {
	const trimmed = value.trim()
	if (!trimmed) return null
	const entries = trimmed
		.split(",")
		.map((tag) => tag.trim())
		.filter((tag) => tag.length > 0)
	return entries.length ? entries : null
}

function parseMetadataInput(value: string): JsonValue | null {
	const trimmed = value.trim()
	if (!trimmed) return null
	try {
		return JSON.parse(trimmed) as JsonValue
	} catch {
		throw new Error("Metadata must be valid JSON")
	}
}

function buildCatalogPayload(draft: AuthenticatorDraft): Omit<CreateAdminAuthenticatorInput, "id"> {
	const sortValue = Number(draft.sortOrder)
	return {
		label: draft.label.trim(),
		description: draft.description.trim() || null,
		factorType: draft.factorType,
		issuer: draft.issuer.trim() || null,
		helper: draft.helper.trim() || null,
		docsUrl: draft.docsUrl.trim() || null,
		tags: parseTagsInput(draft.tags),
		metadata: parseMetadataInput(draft.metadata),
		sortOrder: Number.isFinite(sortValue) ? sortValue : 0,
	}
}

const SUPPORTED_CATEGORIES: SettingsCategory[] = ["general", "monitoring", "auth", "docs", "security"]

function isSettingsCategory(value: unknown): value is SettingsCategory {
	return typeof value === "string" && SUPPORTED_CATEGORIES.includes(value as SettingsCategory)
}

function getMetaRecord(meta: NavigationMenuItem["meta"]): Record<string, unknown> | null {
	if (!meta || typeof meta !== "object" || Array.isArray(meta)) return null
	return meta as Record<string, unknown>
}

function parseSettingsCategory(meta: NavigationMenuItem["meta"]): SettingsCategory | undefined {
	const record = getMetaRecord(meta)
	if (!record) return undefined
	const value = record.settingsCategory
	return isSettingsCategory(value) ? value : undefined
}

function parseSettingsRoute(meta: NavigationMenuItem["meta"]): string | undefined {
	const record = getMetaRecord(meta)
	if (!record) return undefined
	const value = record.settingsRoute
	if (typeof value !== "string") return undefined
	const trimmed = value.trim()
	return trimmed.length ? trimmed : undefined
}

function extractRequiredRoles(meta: NavigationMenuItem["meta"]): string[] | null {
	const record = getMetaRecord(meta)
	if (!record) return null
	const value = record.requiresRoles
	if (!Array.isArray(value)) return null
	return value.filter((role): role is string => typeof role === "string")
}

function userHasAccess(meta: NavigationMenuItem["meta"], roles: string[]): boolean {
	const required = extractRequiredRoles(meta)
	if (!required || required.length === 0) return true
	return required.some((role) => roles.includes(role))
}

function matchesRoute(pathname: string, route: string | undefined): boolean {
	if (!route) return false
	const cleanRoute = route.endsWith("/") && route !== "/" ? route.replace(/\/+$/, "") : route
	const cleanPath = pathname.endsWith("/") && pathname !== "/" ? pathname.replace(/\/+$/, "") : pathname
	return cleanPath === cleanRoute || cleanPath.startsWith(`${cleanRoute}/`)
}

function buildSectionGroups(menu: NavigationMenu | null | undefined, roles: string[]): SectionGroup[] {
	if (!menu) return []
	const filtered = filterNavigationTree(menu.items ?? [])
	const groups: SectionGroup[] = []

	for (const group of filtered) {
		if (!userHasAccess(group.meta, roles)) continue
		const items: SectionNavItem[] = []
		for (const child of group.children ?? []) {
			if (!userHasAccess(child.meta, roles)) continue
			const category = parseSettingsCategory(child.meta)
			const settingsRoute = parseSettingsRoute(child.meta)
			const route = settingsRoute ?? (!category && typeof child.url === "string" ? child.url : undefined)
			items.push({
				id: child.id,
				title: child.title,
				category,
				route,
				icon: resolveIcon(child.icon ?? undefined),
				comingSoon: !category && !route,
				parentTitle: group.title,
			})
		}
		if (items.length) {
			groups.push({ id: group.id, title: group.title, items })
		}
	}

	return groups
}

type SectionSaveHandler = () => Promise<void>

type GeneralSectionProps = {
	state: GeneralState
	setState: React.Dispatch<React.SetStateAction<GeneralState>>
	onSave: SectionSaveHandler
	saving: boolean
}

type MonitoringSectionProps = {
	state: MonitoringState
	setState: React.Dispatch<React.SetStateAction<MonitoringState>>
	onSave: SectionSaveHandler
	saving: boolean
}

type AuthSectionProps = {
	state: AuthState
	setState: React.Dispatch<React.SetStateAction<AuthState>>
	onSave: SectionSaveHandler
	saving: boolean
}

type DocsSectionProps = {
	state: DocsState
	setState: React.Dispatch<React.SetStateAction<DocsState>>
	onSave: SectionSaveHandler
	saving: boolean
}

type SecuritySectionProps = {
	state: SecurityState
	setState: React.Dispatch<React.SetStateAction<SecurityState>>
	onSave: SectionSaveHandler
	saving: boolean
}

function GeneralSettingsSection({ state, setState, onSave, saving }: GeneralSectionProps) {
	return (
		<div className="space-y-4">
			<div className="rounded border p-4 space-y-4">
				<div>
					<label htmlFor="general-appName" className="block text-sm font-medium">App display name</label>
					<input
						id="general-appName"
						className="mt-1 w-full rounded-md border px-3 py-2 bg-background"
						placeholder="Pet Shelter Registry"
						value={state.appName}
						onChange={(event) => setState((prev) => ({ ...prev, appName: event.target.value }))}
					/>
				</div>
				<div>
					<label htmlFor="general-supportEmail" className="block text-sm font-medium">Support email</label>
					<input
						id="general-supportEmail"
						className="mt-1 w-full rounded-md border px-3 py-2 bg-background"
						placeholder="support@example.com"
						value={state.supportEmail}
						onChange={(event) => setState((prev) => ({ ...prev, supportEmail: event.target.value }))}
					/>
				</div>
				<div className="pt-2">
					<Button type="button" size="sm" onClick={() => { void onSave() }} disabled={saving}>
						{saving ? "Saving…" : "Save General"}
					</Button>
				</div>
			</div>
		</div>
	)
}

function MonitoringSettingsSection({ state, setState, onSave, saving }: MonitoringSectionProps) {
	return (
		<div className="space-y-4">
			<div className="rounded border p-4 space-y-4">
				<div>
					<label htmlFor="monitoring-chartsRefreshSec" className="block text-sm font-medium">Charts refresh interval (seconds)</label>
					<input
						id="monitoring-chartsRefreshSec"
						type="number"
						min={5}
						step={5}
						className="mt-1 w-40 rounded-md border px-3 py-2 bg-background"
						placeholder="15"
						value={state.chartsRefreshSec}
						onChange={(event) => setState((prev) => ({ ...prev, chartsRefreshSec: Number(event.target.value) }))}
					/>
					<p className="text-xs text-muted-foreground mt-1">How often the admin charts auto-refresh.</p>
				</div>
				<div>
					<label htmlFor="monitoring-retentionDays" className="block text-sm font-medium">Time series retention (days)</label>
					<input
						id="monitoring-retentionDays"
						type="number"
						min={1}
						step={1}
						className="mt-1 w-40 rounded-md border px-3 py-2 bg-background"
						placeholder="7"
						value={state.retentionDays}
						onChange={(event) => setState((prev) => ({ ...prev, retentionDays: Number(event.target.value) }))}
					/>
					<p className="text-xs text-muted-foreground mt-1">Retention period for MetricPoint records.</p>
				</div>
				<div className="pt-2">
					<Button type="button" size="sm" onClick={() => { void onSave() }} disabled={saving}>
						{saving ? "Saving…" : "Save Monitoring"}
					</Button>
				</div>
			</div>
		</div>
	)
}

function AuthSettingsSection({ state, setState, onSave, saving }: AuthSectionProps) {
	const catalogQuery = useAuthenticatorCatalog(true)
	const createAuthenticator = useCreateAuthenticator()
	const updateAuthenticator = useUpdateAuthenticator()
	const archiveAuthenticator = useArchiveAuthenticator()
	const restoreAuthenticator = useRestoreAuthenticator()

	const catalogEntries = React.useMemo(() => {
		const entries = catalogQuery.data ?? []
		const sorted = [...entries]
		sorted.sort((a, b) => {
			const order = (a.sortOrder ?? 0) - (b.sortOrder ?? 0)
			if (order !== 0) return order
			return a.label.localeCompare(b.label)
		})
		return sorted
	}, [catalogQuery.data])

	const catalogMap = React.useMemo(
		() => new Map(catalogEntries.map((entry) => [entry.id, entry] as const)),
		[catalogEntries]
	)

	const selectedAuthenticators = React.useMemo<CatalogDisplayEntry[]>(
		() => state.authenticators.map((id) => catalogMap.get(id) ?? buildMissingCatalogEntry(id)),
		[state.authenticators, catalogMap]
	)
	const missingAuthenticatorCount = React.useMemo(
		() => selectedAuthenticators.filter((entry) => entry._missing).length,
		[selectedAuthenticators]
	)

	const availableAuthenticators = React.useMemo(
		() => catalogEntries.filter((entry) => !entry.isArchived && !state.authenticators.includes(entry.id)),
		[catalogEntries, state.authenticators]
	)

	const activeCatalogEntries = React.useMemo(
		() => catalogEntries.filter((entry) => !entry.isArchived),
		[catalogEntries]
	)

	const archivedCatalogEntries = React.useMemo(
		() => catalogEntries.filter((entry) => entry.isArchived),
		[catalogEntries]
	)

	const selectedModeMeta = React.useMemo(
		() => LOGIN_MODE_OPTIONS.find((option) => option.value === state.mode),
		[state.mode]
	)

	const policyCopy = React.useMemo(() => MFA_POLICY_COPY[state.enforceMfa], [state.enforceMfa])

	const activeOauthCount = (state.google ? 1 : 0) + (state.github ? 1 : 0)

	const [pendingAuthenticator, setPendingAuthenticator] = React.useState<string>("")
	const [catalogDialog, setCatalogDialog] = React.useState<CatalogDialogState>(null)
	const [catalogDraft, setCatalogDraft] = React.useState<AuthenticatorDraft>(() => createEmptyCatalogDraft())
	const [catalogFormError, setCatalogFormError] = React.useState<string | null>(null)
	const [catalogSubmitting, setCatalogSubmitting] = React.useState(false)
	const [catalogAction, setCatalogAction] = React.useState<{ id: string; type: "archive" | "restore" } | null>(null)
	const [catalogActionError, setCatalogActionError] = React.useState<string | null>(null)
	const [showArchivedCatalog, setShowArchivedCatalog] = React.useState(false)

	React.useEffect(() => {
		if (!availableAuthenticators.length) {
			if (pendingAuthenticator) setPendingAuthenticator("")
			return
		}
		const stillValid = pendingAuthenticator && availableAuthenticators.some((entry) => entry.id === pendingAuthenticator)
		if (stillValid) return
		setPendingAuthenticator(availableAuthenticators[0]?.id ?? "")
	}, [availableAuthenticators, pendingAuthenticator])

	const catalogLoading = catalogQuery.isLoading
	const catalogError = catalogQuery.isError
		? (catalogQuery.error instanceof Error ? catalogQuery.error : new Error("Failed to load authenticator catalog"))
		: null

	const handleAddAuthenticator = React.useCallback(() => {
		if (!pendingAuthenticator) return
		setState((prev) => {
			if (prev.authenticators.includes(pendingAuthenticator)) return prev
			return { ...prev, authenticators: [...prev.authenticators, pendingAuthenticator] }
		})
	}, [pendingAuthenticator, setState])

	const handleRemoveAuthenticator = React.useCallback(
		(id: string) => {
			setState((prev) => ({ ...prev, authenticators: prev.authenticators.filter((entry) => entry !== id) }))
		},
		[setState]
	)

	const openCreateDialog = React.useCallback(() => {
		setCatalogDialog({ mode: "create" })
		setCatalogDraft(createEmptyCatalogDraft())
		setCatalogFormError(null)
	}, [])

	const openEditDialog = React.useCallback((entry: AdminAuthenticatorCatalogRecord) => {
		setCatalogDialog({ mode: "edit", entry })
		setCatalogDraft(draftFromCatalogEntry(entry))
		setCatalogFormError(null)
	}, [])

	const closeCatalogDialog = React.useCallback(() => {
		setCatalogDialog(null)
		setCatalogFormError(null)
	}, [])

	const handleDraftChange = React.useCallback((field: keyof AuthenticatorDraft, value: string) => {
		setCatalogDraft((prev) => ({ ...prev, [field]: value }))
	}, [])

	const submitCatalogForm = React.useCallback(async () => {
		if (!catalogDialog) return
		setCatalogFormError(null)
		const trimmedLabel = catalogDraft.label.trim()
		if (!trimmedLabel) {
			setCatalogFormError("Label is required.")
			return
		}
		const targetId = catalogDraft.id.trim()
		if (catalogDialog.mode === "create") {
			if (!targetId) {
				setCatalogFormError("Authenticator ID is required.")
				return
			}
			if (!AUTH_ID_PATTERN.test(targetId)) {
				setCatalogFormError("Authenticator ID must use letters, numbers, dashes, or underscores.")
				return
			}
		}
		let payload: Omit<CreateAdminAuthenticatorInput, "id">
		try {
			payload = buildCatalogPayload({ ...catalogDraft, label: trimmedLabel })
		} catch (err) {
			setCatalogFormError(err instanceof Error ? err.message : "Metadata must be valid JSON")
			return
		}
		try {
			setCatalogSubmitting(true)
			if (catalogDialog.mode === "create") {
				const input: CreateAdminAuthenticatorInput = { id: targetId, ...payload }
				await createAuthenticator.mutateAsync(input)
			} else {
				const updateInput: UpdateAdminAuthenticatorInput = { ...payload }
				const id = catalogDialog.entry?.id ?? targetId
				await updateAuthenticator.mutateAsync({ id, input: updateInput })
			}
			closeCatalogDialog()
		} catch (err) {
			setCatalogFormError(err instanceof Error ? err.message : "Failed to save authenticator")
		} finally {
			setCatalogSubmitting(false)
		}
	}, [catalogDialog, catalogDraft, createAuthenticator, updateAuthenticator, closeCatalogDialog])

	const handleArchiveCatalog = React.useCallback(async (entry: AdminAuthenticatorCatalogRecord) => {
		setCatalogAction({ id: entry.id, type: "archive" })
		setCatalogActionError(null)
		try {
			await archiveAuthenticator.mutateAsync(entry.id)
		} catch (err) {
			setCatalogActionError(err instanceof Error ? err.message : "Failed to archive authenticator")
		} finally {
			setCatalogAction(null)
		}
	}, [archiveAuthenticator])

	const handleRestoreCatalog = React.useCallback(async (entry: AdminAuthenticatorCatalogRecord) => {
		setCatalogAction({ id: entry.id, type: "restore" })
		setCatalogActionError(null)
		try {
			await restoreAuthenticator.mutateAsync(entry.id)
		} catch (err) {
			setCatalogActionError(err instanceof Error ? err.message : "Failed to restore authenticator")
		} finally {
			setCatalogAction(null)
		}
	}, [restoreAuthenticator])

	const actionIsPending = React.useCallback(
		(entry: AdminAuthenticatorCatalogRecord, type: "archive" | "restore") =>
			catalogAction?.id === entry.id && catalogAction.type === type,
		[catalogAction]
	)

	const handleOauthToggle = React.useCallback(
		(key: keyof Pick<AuthState, "google" | "github">, checked: boolean) => {
			setState((prev) => ({ ...prev, [key]: checked }))
		},
		[setState]
	)

	return (
		<div className="space-y-6">
			<div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
				{AUTH_RUN_STATES.map((stateMeta) => {
					const status = stateMeta.compute({
						state,
						activeOauthCount,
						authenticatorCount: state.authenticators.length,
						missingAuthenticatorCount,
					})
					return (
						<Card key={stateMeta.id} className="border-dashed">
							<CardHeader className="flex items-center justify-between gap-3 space-y-0">
								<div>
									<CardTitle className="text-base">{stateMeta.title}</CardTitle>
									<CardDescription>{status.helper}</CardDescription>
								</div>
								<stateMeta.icon className="h-5 w-5 text-muted-foreground" aria-hidden="true" />
							</CardHeader>
							<CardContent className="pt-0">
								<Badge variant={status.variant}>{status.label}</Badge>
							</CardContent>
						</Card>
					)
				})}
			</div>
			<div className="grid gap-4 lg:grid-cols-2">
				<Card>
					<CardHeader>
						<div className="flex items-start justify-between gap-3">
							<div>
								<CardTitle>Login mode</CardTitle>
								<CardDescription>Choose how operator sessions issue tokens.</CardDescription>
							</div>
							<Badge variant="secondary" className="uppercase tracking-wide text-[11px]">
								{selectedModeMeta?.badge ?? state.mode}
							</Badge>
						</div>
					</CardHeader>
					<CardContent className="space-y-3">
						<RadioGroup value={state.mode} onValueChange={(value) => setState((prev) => ({ ...prev, mode: value as AuthState["mode"] }))}>
							{LOGIN_MODE_OPTIONS.map((option) => {
								const modeId = `auth-mode-${option.value}`
								return (
									<div key={option.value} className="flex items-start gap-3 rounded-lg border p-3">
										<RadioGroupItem id={modeId} value={option.value} className="mt-1" />
										<div className="space-y-1">
											<Label htmlFor={modeId} className="flex items-center gap-2 text-base">
												{option.title}
												<Badge
													variant={option.value === state.mode ? "default" : "outline"}
													className="text-[11px] uppercase tracking-wide"
												>
													{option.badge}
												</Badge>
											</Label>
											<p className="text-sm text-muted-foreground">{option.description}</p>
										</div>
									</div>
								)
							})}
						</RadioGroup>
					</CardContent>
				</Card>
				<Card>
					<CardHeader>
						<div className="flex items-start justify-between gap-3">
							<div>
								<CardTitle>MFA enrollment</CardTitle>
								<CardDescription>Set the policy the Security workspace enforces.</CardDescription>
							</div>
							<Badge variant="secondary" className="uppercase tracking-wide text-[11px]">
								{policyCopy.label}
							</Badge>
						</div>
					</CardHeader>
					<CardContent className="space-y-3">
						<Label htmlFor="auth-mfa-policy">MFA enrollment policy</Label>
						<select
							id="auth-mfa-policy"
							className="mt-1 w-full rounded-md border px-3 py-2 bg-background"
							value={state.enforceMfa}
							onChange={(event) => setState((prev) => ({ ...prev, enforceMfa: event.target.value as AuthMfaPolicy }))}
						>
							<option value="optional">Optional — show reminders only</option>
							<option value="recommended">Recommended — nudge monthly</option>
							<option value="required">Required — block login without MFA</option>
						</select>
						<p className="text-xs text-muted-foreground">{policyCopy.helper}</p>
					</CardContent>
				</Card>
			</div>
			<Card>
				<CardHeader>
					<div className="flex items-start justify-between gap-3">
						<div>
							<CardTitle>OAuth providers</CardTitle>
							<CardDescription>Flip providers on once their credentials are configured.</CardDescription>
						</div>
						<Badge variant="secondary">{activeOauthCount} enabled</Badge>
					</div>
				</CardHeader>
				<CardContent className="space-y-3">
					{OAUTH_PROVIDERS.map((provider) => {
						const switchId = `auth-oauth-${provider.key}`
						const enabled = state[provider.key]
						return (
							<div key={provider.key} className="flex flex-col gap-3 rounded-lg border p-3 sm:flex-row sm:items-center sm:justify-between">
								<div className="flex-1">
									<Label htmlFor={switchId} className="flex items-center gap-2 text-base">
										{provider.label}
										<Badge variant={enabled ? "default" : "outline"} className="text-[11px] uppercase tracking-wide">
											{enabled ? "Enabled" : "Disabled"}
										</Badge>
									</Label>
									<p className="text-sm text-muted-foreground">{provider.description}</p>
								</div>
								<Switch
									id={switchId}
									checked={enabled}
									onCheckedChange={(checked) => handleOauthToggle(provider.key, checked)}
									aria-label={`${provider.label} OAuth toggle`}
								/>
							</div>
						)
					})}
					<p className="text-xs text-muted-foreground">Enable providers only after their client IDs, secrets, and redirect URIs are configured.</p>
				</CardContent>
			</Card>
			<Card>
				<CardHeader>
					<div className="flex flex-wrap items-center justify-between gap-3">
						<div>
							<CardTitle>Enabled authenticators</CardTitle>
							<CardDescription>Surface only the factors you have vetted for your org.</CardDescription>
						</div>
						<Badge variant="secondary">{state.authenticators.length} enabled</Badge>
					</div>
				</CardHeader>
				<CardContent className="space-y-4">
					{catalogLoading ? <p className="text-sm text-muted-foreground">Loading catalog…</p> : null}
					{catalogError ? (
						<Alert variant="destructive">
							<AlertTitle>Unable to load catalog</AlertTitle>
							<AlertDescription>{catalogError.message}</AlertDescription>
						</Alert>
					) : null}
					<div className="space-y-2">
						{selectedAuthenticators.length ? (
							selectedAuthenticators.map((entry) => (
								<div key={entry.id} data-testid={`enabled-authenticator-${entry.id}`} className="flex flex-col gap-2 rounded-lg border p-3 sm:flex-row sm:items-center">
									<div className="flex-1">
										<div className="flex flex-wrap items-center gap-2">
											<p className="font-medium">{entry.label}</p>
											<Badge variant="secondary" className="uppercase tracking-wide text-[11px]">
												{entry.factorType.replace(/_/g, " ")}
											</Badge>
											{entry.isArchived ? (
												<Badge variant="outline" className="text-destructive border-destructive/40">Archived</Badge>
											) : null}
											{entry._missing ? (
												<Badge variant="outline" className="text-amber-600 border-amber-500/40 bg-amber-50">Missing</Badge>
											) : null}
										</div>
										<p className="text-xs text-muted-foreground mt-1">{entry.description ?? "No description available."}</p>
										{entry.helper ? (
											<p className="text-[11px] text-muted-foreground">{entry.helper}</p>
										) : null}
									</div>
									<Button
										type="button"
										variant="ghost"
										size="sm"
										className="self-start text-destructive hover:text-destructive"
										onClick={() => handleRemoveAuthenticator(entry.id)}
										aria-label={`Remove ${entry.label}`}
									>
										<X className="mr-1.5 h-4 w-4" />
										Remove
									</Button>
								</div>
							))
						) : (
							<p className="text-sm text-muted-foreground">No authenticators enabled yet. Start by adding a TOTP app to unblock enrollment.</p>
						)}
					</div>
				</CardContent>
				<CardFooter className="flex flex-wrap items-center gap-2">
					<select
						id="authenticator-add-select"
						aria-label="Authenticator to add"
						className="rounded-md border px-3 py-2 bg-background"
						value={pendingAuthenticator}
						onChange={(event) => setPendingAuthenticator(event.target.value)}
						disabled={!availableAuthenticators.length}
					>
						{availableAuthenticators.length === 0 ? (
							<option value="">All catalog authenticators are enabled</option>
						) : (
							availableAuthenticators.map((entry) => (
								<option key={entry.id} value={entry.id}>{entry.label}</option>
							))
						)}
					</select>
					<Button
						type="button"
						variant="outline"
						size="sm"
						onClick={handleAddAuthenticator}
						disabled={!pendingAuthenticator}
					>
						Add authenticator
					</Button>
				</CardFooter>
			</Card>
				<Card>
					<CardHeader className="flex flex-wrap items-center justify-between gap-3">
						<div>
							<CardTitle>Authenticator catalog</CardTitle>
							<CardDescription>Add or edit the entries admins can select.</CardDescription>
						</div>
					<Button type="button" variant="outline" size="sm" onClick={openCreateDialog}>
						New authenticator
					</Button>
				</CardHeader>
				<CardContent className="space-y-4">
					{catalogActionError ? <p className="text-sm text-destructive">{catalogActionError}</p> : null}
					{activeCatalogEntries.length ? (
						<div className="space-y-3">
							{activeCatalogEntries.map((entry) => (
								<div key={entry.id} data-testid={`catalog-entry-${entry.id}`} className="rounded-lg border p-3">
									<div className="flex flex-wrap items-center gap-3">
										<div className="flex-1">
											<p className="text-sm font-medium">{entry.label}</p>
											<p className="text-xs text-muted-foreground">{entry.description ?? "No description provided."}</p>
										</div>
										<div className="flex flex-wrap gap-2">
											<Button type="button" size="sm" variant="secondary" onClick={() => openEditDialog(entry)}>
												Edit
											</Button>
											<Button
												type="button"
												variant="ghost"
												className="text-destructive hover:text-destructive"
												onClick={() => handleArchiveCatalog(entry)}
												disabled={actionIsPending(entry, "archive")}
											>
												{actionIsPending(entry, "archive") ? "Archiving…" : "Archive"}
											</Button>
										</div>
									</div>
									{entry.helper ? <p className="text-xs text-muted-foreground mt-2">{entry.helper}</p> : null}
									{entry.tags?.length ? (
										<p className="text-[11px] uppercase tracking-wide text-muted-foreground mt-1">Tags: {entry.tags.join(", ")}</p>
									) : null}
								</div>
							))}
						</div>
					) : (
						<p className="text-sm text-muted-foreground">No active catalog entries yet.</p>
					)}
					{archivedCatalogEntries.length ? (
						<div className="border-t pt-4">
							<Button
								type="button"
								variant="ghost"
								size="sm"
								onClick={() => setShowArchivedCatalog((prev) => !prev)}
							>
								{showArchivedCatalog
									? "Hide archived authenticators"
									: `Show archived authenticators (${archivedCatalogEntries.length})`}
							</Button>
							{showArchivedCatalog ? (
								<div className="mt-3 space-y-3">
									{archivedCatalogEntries.map((entry) => (
										<div key={`${entry.id}-archived`} data-testid={`catalog-entry-${entry.id}-archived`} className="rounded-lg border border-dashed p-3">
											<div className="flex flex-wrap items-center gap-2">
												<p className="text-sm font-medium text-muted-foreground">{entry.label}</p>
												<Button type="button" variant="secondary" size="sm" onClick={() => openEditDialog(entry)}>
													Edit
												</Button>
												<Button
													type="button"
													variant="outline"
													onClick={() => handleRestoreCatalog(entry)}
													disabled={actionIsPending(entry, "restore")}
												>
													{actionIsPending(entry, "restore") ? "Restoring…" : "Restore"}
												</Button>
											</div>
											<p className="text-xs text-muted-foreground mt-1">{entry.description ?? "No description provided."}</p>
										</div>
									))}
								</div>
							) : null}
						</div>
					) : null}
				</CardContent>
			</Card>
			<div className="flex flex-col gap-3 border border-dashed rounded-lg p-4 sm:flex-row sm:items-center sm:justify-between">
				<p className="text-sm text-muted-foreground">
					Authentication changes apply to all administrators immediately.
				</p>
				<Button type="button" size="sm" onClick={() => { void onSave() }} disabled={saving}>
					{saving ? "Saving…" : "Save Authentication"}
				</Button>
			</div>
			<Dialog open={Boolean(catalogDialog)} onOpenChange={(open) => { if (!open) closeCatalogDialog() }}>
				<DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
					<DialogHeader>
						<DialogTitle>{catalogDialog?.mode === "create" ? "Add authenticator" : "Edit authenticator"}</DialogTitle>
						<DialogDescription>Define the presets that admins and end users will see when enabling MFA.</DialogDescription>
					</DialogHeader>
					<div className="space-y-4">
						<div className="grid gap-4 sm:grid-cols-2">
							<div>
								<label className="text-sm font-medium" htmlFor="catalog-id">Identifier</label>
								<Input
									id="catalog-id"
									value={catalogDraft.id}
									onChange={(event) => handleDraftChange("id", event.target.value)}
									disabled={catalogDialog?.mode === "edit"}
									placeholder="google"
								/>
								<p className="text-xs text-muted-foreground mt-1">Machine-friendly slug shared with the Security API.</p>
							</div>
							<div>
								<label className="text-sm font-medium" htmlFor="catalog-label">Display label</label>
								<Input
									id="catalog-label"
									value={catalogDraft.label}
									onChange={(event) => handleDraftChange("label", event.target.value)}
									placeholder="Google Authenticator"
								/>
							</div>
						</div>
						<div className="grid gap-4 sm:grid-cols-2">
							<div>
								<label className="text-sm font-medium" htmlFor="catalog-factor">Factor type</label>
								<select
									id="catalog-factor"
									className="mt-1 w-full rounded-md border px-3 py-2 bg-background"
									value={catalogDraft.factorType}
									onChange={(event) => handleDraftChange("factorType", event.target.value)}
								>
									{FACTOR_TYPE_OPTIONS.map((option) => (
										<option key={option.value} value={option.value}>{option.label}</option>
									))}
								</select>
							</div>
							<div>
								<label className="text-sm font-medium" htmlFor="catalog-sort">Sort order</label>
								<Input
									id="catalog-sort"
									type="number"
									value={catalogDraft.sortOrder}
									onChange={(event) => handleDraftChange("sortOrder", event.target.value)}
								/>
								<p className="text-xs text-muted-foreground mt-1">Lower values appear first in dropdowns.</p>
							</div>
						</div>
						<div>
							<label className="text-sm font-medium" htmlFor="catalog-description">Description</label>
							<Textarea
								id="catalog-description"
								value={catalogDraft.description}
								onChange={(event) => handleDraftChange("description", event.target.value)}
								rows={3}
								placeholder="Recommended mobile authenticator"
							/>
						</div>
						<div className="grid gap-4 sm:grid-cols-2">
							<div>
								<label className="text-sm font-medium" htmlFor="catalog-issuer">Issuer</label>
								<Input
									id="catalog-issuer"
									value={catalogDraft.issuer}
									onChange={(event) => handleDraftChange("issuer", event.target.value)}
							/>
							</div>
							<div>
								<label className="text-sm font-medium" htmlFor="catalog-docs">Docs URL</label>
								<Input
									id="catalog-docs"
									value={catalogDraft.docsUrl}
									onChange={(event) => handleDraftChange("docsUrl", event.target.value)}
								placeholder="https://support.google.com/..."
							/>
							</div>
						</div>
						<div>
							<label className="text-sm font-medium" htmlFor="catalog-helper">Helper text</label>
							<Textarea
								id="catalog-helper"
								value={catalogDraft.helper}
								onChange={(event) => handleDraftChange("helper", event.target.value)}
								rows={2}
								placeholder="Remind users to store backup codes"
							/>
						</div>
						<div className="grid gap-4 sm:grid-cols-2">
							<div>
								<label className="text-sm font-medium" htmlFor="catalog-tags">Tags</label>
								<Input
									id="catalog-tags"
									value={catalogDraft.tags}
									onChange={(event) => handleDraftChange("tags", event.target.value)}
									placeholder="totp, recommended"
							/>
								<p className="text-xs text-muted-foreground mt-1">Comma-separated values.</p>
							</div>
							<div>
								<label className="text-sm font-medium" htmlFor="catalog-metadata">Metadata (JSON)</label>
								<Textarea
									id="catalog-metadata"
									value={catalogDraft.metadata}
									onChange={(event) => handleDraftChange("metadata", event.target.value)}
									rows={4}
									className="font-mono text-xs"
									placeholder='{"platforms":["ios","android"]}'
								/>
							</div>
						</div>
					</div>
					{catalogFormError ? <p className="text-sm text-destructive">{catalogFormError}</p> : null}
					<DialogFooter>
						<Button type="button" variant="ghost" onClick={closeCatalogDialog}>Cancel</Button>
						<Button type="button" onClick={() => { void submitCatalogForm() }} disabled={catalogSubmitting}>
							{catalogSubmitting ? "Saving…" : catalogDialog?.mode === "create" ? "Create" : "Save"}
						</Button>
					</DialogFooter>
				</DialogContent>
			</Dialog>
		</div>
	)
}

function DocsSettingsSection({ state, setState, onSave, saving }: DocsSectionProps) {
	return (
		<div className="space-y-4">
			<div className="rounded border p-4 space-y-4">
				<div>
					<label className="block text-sm font-medium">Expose public Docs link</label>
					<label className="mt-1 inline-flex items-center gap-2 text-sm">
						<input
							type="checkbox"
							className="accent-foreground"
							checked={state.showPublicDocsLink}
							onChange={(event) => setState((prev) => ({ ...prev, showPublicDocsLink: event.target.checked }))}
						/>
						Show Pets REST API in sidebar
					</label>
				</div>
				<div className="pt-2">
					<Button type="button" size="sm" onClick={() => { void onSave() }} disabled={saving}>
						{saving ? "Saving…" : "Save Documentation"}
					</Button>
				</div>
			</div>
		</div>
	)
}

function SecuritySettingsSection({ state, setState, onSave, saving }: SecuritySectionProps) {
	return (
		<div className="space-y-4">
			<div className="rounded border p-4 space-y-4">
				<div>
					<label htmlFor="security-sessionMaxAgeMin" className="block text-sm font-medium">Session max age (minutes)</label>
					<input
						id="security-sessionMaxAgeMin"
						type="number"
						min={5}
						step={5}
						className="mt-1 w-40 rounded-md border px-3 py-2 bg-background"
						placeholder="60"
						value={state.sessionMaxAgeMin}
						onChange={(event) => setState((prev) => ({ ...prev, sessionMaxAgeMin: Number(event.target.value) }))}
					/>
				</div>
				<div>
					<label className="block text-sm font-medium">Require email verification</label>
					<label htmlFor="security-requireEmailVerification" className="mt-1 inline-flex items-center gap-2 text-sm">
						<input
							id="security-requireEmailVerification"
							type="checkbox"
							className="accent-foreground"
							checked={state.requireEmailVerification}
							onChange={(event) => setState((prev) => ({ ...prev, requireEmailVerification: event.target.checked }))}
						/>
						Enforce verification before login
					</label>
				</div>
				<div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
					<div>
						<label htmlFor="security-loginIpWindowSec" className="block text-sm font-medium">Login IP window (seconds)</label>
						<input
							id="security-loginIpWindowSec"
							type="number"
							min={10}
							step={10}
							className="mt-1 w-40 rounded-md border px-3 py-2 bg-background"
							value={state.loginIpWindowSec}
							onChange={(event) => setState((prev) => ({ ...prev, loginIpWindowSec: Number(event.target.value) }))}
						/>
					</div>
					<div>
						<label htmlFor="security-loginIpLimit" className="block text-sm font-medium">Login IP limit (attempts)</label>
						<input
							id="security-loginIpLimit"
							type="number"
							min={1}
							step={1}
							className="mt-1 w-40 rounded-md border px-3 py-2 bg-background"
							value={state.loginIpLimit}
							onChange={(event) => setState((prev) => ({ ...prev, loginIpLimit: Number(event.target.value) }))}
						/>
					</div>
					<div>
						<label htmlFor="security-loginLockWindowSec" className="block text-sm font-medium">Lock window (seconds)</label>
						<input
							id="security-loginLockWindowSec"
							type="number"
							min={30}
							step={30}
							className="mt-1 w-40 rounded-md border px-3 py-2 bg-background"
							value={state.loginLockWindowSec}
							onChange={(event) => setState((prev) => ({ ...prev, loginLockWindowSec: Number(event.target.value) }))}
						/>
					</div>
					<div>
						<label htmlFor="security-loginLockThreshold" className="block text-sm font-medium">Lock threshold (failures)</label>
						<input
							id="security-loginLockThreshold"
							type="number"
							min={1}
							step={1}
							className="mt-1 w-40 rounded-md border px-3 py-2 bg-background"
							value={state.loginLockThreshold}
							onChange={(event) => setState((prev) => ({ ...prev, loginLockThreshold: Number(event.target.value) }))}
						/>
					</div>
					<div>
						<label htmlFor="security-loginLockDurationMin" className="block text-sm font-medium">Lock duration (minutes)</label>
						<input
							id="security-loginLockDurationMin"
							type="number"
							min={1}
							step={1}
							className="mt-1 w-40 rounded-md border px-3 py-2 bg-background"
							value={state.loginLockDurationMin}
							onChange={(event) => setState((prev) => ({ ...prev, loginLockDurationMin: Number(event.target.value) }))}
						/>
					</div>
					<div>
						<label htmlFor="security-passwordHistoryLimit" className="block text-sm font-medium">Password history limit</label>
						<input
							id="security-passwordHistoryLimit"
							type="number"
							min={0}
							step={1}
							className="mt-1 w-40 rounded-md border px-3 py-2 bg-background"
							value={state.passwordHistoryLimit}
							onChange={(event) => setState((prev) => ({ ...prev, passwordHistoryLimit: Number(event.target.value) }))}
						/>
						<p className="text-xs text-muted-foreground mt-1">How many previous passwords are disallowed on reset.</p>
					</div>
				</div>
				<div className="pt-2">
					<Button type="button" size="sm" onClick={() => { void onSave() }} disabled={saving}>
						{saving ? "Saving…" : "Save Security"}
					</Button>
				</div>
			</div>
		</div>
	)
}

export default function AdminSettingsPage() {
	const { user } = useAuth()
	const userRoles = React.useMemo(() => user?.roles ?? [], [user])
	const canManageNavigation = React.useMemo(
		() => Boolean(user?.roles?.some((role) => role === "admin" || role === "system_admin")),
		[user]
	)

	const { data: settingsData, isLoading: settingsLoading, error: settingsError } = useAdminSettings()
	const saveMutation = useSaveAdminSettings()
	const settingsMenuQuery = useNavigationMenu("settings_main")
	const location = useLocation()
	const navigate = useNavigate()
	const [searchParams, setSearchParams] = useSearchParams()
	const outlet = useOutlet()

	const [general, setGeneral] = React.useState<GeneralState>({ appName: "Pet Shelter Registry", supportEmail: "" })
	const [monitoring, setMonitoring] = React.useState<MonitoringState>({ chartsRefreshSec: 15, retentionDays: 7 })
	const [auth, setAuthSettings] = React.useState<AuthState>({
		mode: "session",
		google: false,
		github: false,
		enforceMfa: "recommended",
		authenticators: [...DEFAULT_ENABLED_AUTHENTICATORS],
	})
	const [docs, setDocs] = React.useState<DocsState>({ showPublicDocsLink: true })
	const [security, setSecurity] = React.useState<SecurityState>({
		sessionMaxAgeMin: 60,
		requireEmailVerification: true,
		loginIpWindowSec: 60,
		loginIpLimit: 20,
		loginLockWindowSec: 15 * 60,
		loginLockThreshold: 5,
		loginLockDurationMin: 15,
		passwordHistoryLimit: 10,
	})
	const [saving, setSaving] = React.useState<SettingsCategory | null>(null)
	const [filter, setFilter] = React.useState<string>(() => searchParams.get("q") ?? "")
	const activeSectionRef = React.useRef<HTMLButtonElement | null>(null)
	const ignoreRouteSyncRef = React.useRef(false)
	const commitSearchParams = React.useCallback(
		(updater: (params: URLSearchParams) => void) => {
			const params = new URLSearchParams(searchParams)
			const before = params.toString()
			updater(params)
			if (params.toString() !== before) {
				setSearchParams(params)
			}
		},
		[searchParams, setSearchParams]
	)

	React.useEffect(() => {
		if (!settingsData) return
		const s = settingsData
		if (s.general) {
			setGeneral({
				appName: String(s.general.appName ?? "Pet Shelter Registry"),
				supportEmail: String(s.general.supportEmail ?? ""),
			})
		}
		if (s.monitoring) {
			setMonitoring({
				chartsRefreshSec: Number(s.monitoring.chartsRefreshSec ?? 15),
				retentionDays: Number(s.monitoring.retentionDays ?? 7),
			})
		}
		if (s.auth) {
			const allowedAuthenticators = coerceAuthenticatorSelection((s.auth.authenticators as unknown) ?? null)
			const rawPolicy = typeof s.auth.enforceMfa === "string" ? s.auth.enforceMfa : ""
			const enforceMfa: AuthMfaPolicy = rawPolicy === "optional" || rawPolicy === "required" || rawPolicy === "recommended"
				? rawPolicy
				: "recommended"
			setAuthSettings({
				mode: s.auth.mode === "jwt" ? "jwt" : "session",
				google: Boolean(s.auth.google),
				github: Boolean(s.auth.github),
				enforceMfa,
				authenticators: allowedAuthenticators,
			})
		}
		if (s.docs) {
			setDocs({ showPublicDocsLink: Boolean(s.docs.showPublicDocsLink ?? true) })
		}
		if (s.security) {
			setSecurity({
				sessionMaxAgeMin: Number(s.security.sessionMaxAgeMin ?? 60),
				requireEmailVerification: Boolean(s.security.requireEmailVerification ?? true),
				loginIpWindowSec: Number(s.security.loginIpWindowSec ?? 60),
				loginIpLimit: Number(s.security.loginIpLimit ?? 20),
				loginLockWindowSec: Number(s.security.loginLockWindowSec ?? 15 * 60),
				loginLockThreshold: Number(s.security.loginLockThreshold ?? 5),
				loginLockDurationMin: Number(s.security.loginLockDurationMin ?? 15),
				passwordHistoryLimit: Number(s.security.passwordHistoryLimit ?? 10),
			})
		}
	}, [settingsData])

	React.useEffect(() => {
		const query = searchParams.get("q") ?? ""
		setFilter((prev) => (prev === query ? prev : query))
	}, [searchParams])

	const handleFilterChange = React.useCallback(
		(event: React.ChangeEvent<HTMLInputElement>) => {
			const value = event.target.value
			setFilter(value)
			commitSearchParams((params) => {
				if (value) {
					params.set("q", value)
				} else {
					params.delete("q")
				}
			})
		},
		[commitSearchParams]
	)

	const normalizedFilter = React.useMemo(() => filter.trim().toLowerCase(), [filter])
	const sectionGroups = React.useMemo(
		() => buildSectionGroups(settingsMenuQuery.data, userRoles),
		[settingsMenuQuery.data, userRoles]
	)
	const filteredSectionGroups = React.useMemo(() => {
		if (!normalizedFilter) return sectionGroups
		return sectionGroups
			.map((group) => {
				const matchesGroupTitle = group.title.toLowerCase().includes(normalizedFilter)
				const items = group.items.filter((item) => {
					if (matchesGroupTitle) return true
					const lowerTitle = item.title.toLowerCase()
					const lowerParent = item.parentTitle.toLowerCase()
					return lowerTitle.includes(normalizedFilter) || lowerParent.includes(normalizedFilter)
				})
				if (!items.length) return null
				return { ...group, items }
			})
			.filter((group): group is SectionGroup => Boolean(group))
	}, [sectionGroups, normalizedFilter])
	const flatItems = React.useMemo(() => sectionGroups.flatMap((group) => group.items), [sectionGroups])
	const categoryItems = React.useMemo(
		() => flatItems.filter((item): item is SectionNavItem & { category: SettingsCategory } => Boolean(item.category)),
		[flatItems]
	)
	const filteredCategoryItems = React.useMemo(
		() =>
			filteredSectionGroups
				.flatMap((group) => group.items)
				.filter((item): item is SectionNavItem & { category: SettingsCategory } => Boolean(item.category)),
		[filteredSectionGroups]
	)
	const candidateCategoryItems = normalizedFilter ? filteredCategoryItems : categoryItems
	const hasFilter = Boolean(normalizedFilter)

	const [activeItemId, setActiveItemId] = React.useState<string | null>(null)

	const matchedRouteItem = React.useMemo(
		() => flatItems.find((item) => matchesRoute(location.pathname, item.route)) ?? null,
		[flatItems, location.pathname]
	)

	React.useEffect(() => {
		if (ignoreRouteSyncRef.current) {
			if (!matchedRouteItem) {
				ignoreRouteSyncRef.current = false
			}
			return
		}
		if (!matchedRouteItem) return
		if (matchedRouteItem.id === activeItemId) return
		setActiveItemId(matchedRouteItem.id)
	}, [matchedRouteItem, activeItemId])

	React.useEffect(() => {
		const firstCategoryItem = candidateCategoryItems[0] ?? null
		const activeIsCategory = candidateCategoryItems.some((item) => item.id === activeItemId)
		if (!candidateCategoryItems.length) {
			if (!matchedRouteItem && activeItemId !== null) {
				setActiveItemId(null)
			}
			return
		}
		if (!activeItemId && firstCategoryItem) {
			setActiveItemId(firstCategoryItem.id)
			return
		}
		if (matchedRouteItem) return
		if (activeItemId && !activeIsCategory && firstCategoryItem && firstCategoryItem.id !== activeItemId) {
			setActiveItemId(firstCategoryItem.id)
		}
	}, [candidateCategoryItems, activeItemId, matchedRouteItem])

	const activeNavItem = React.useMemo(
		() => flatItems.find((item) => item.id === activeItemId) ?? null,
		[flatItems, activeItemId]
	)

	React.useEffect(() => {
		if (!activeNavItem) return
		if (!activeSectionRef.current) return
		activeSectionRef.current.scrollIntoView({ behavior: "smooth", block: "nearest" })
	}, [activeNavItem])

	const activeCategory = activeNavItem?.category ?? null
	const handleSelectNavItem = React.useCallback(
		(item: SectionNavItem) => {
			if (!item.category) return
			if (location.pathname !== "/settings") {
				ignoreRouteSyncRef.current = true
			}
			setActiveItemId(item.id)
			if (location.pathname !== "/settings") {
				navigate(`/settings${location.search ?? ""}`)
			} else {
				ignoreRouteSyncRef.current = false
			}
		},
		[location.pathname, location.search, navigate]
	)

	const saveCategory = React.useCallback(
		async (category: SettingsCategory) => {
			try {
				setSaving(category)
				switch (category) {
					case "general":
						await saveMutation.mutateAsync({
							category: "general",
							entries: [
								{ key: "appName", value: general.appName },
								{ key: "supportEmail", value: general.supportEmail },
							],
						})
						break
					case "monitoring":
						await saveMutation.mutateAsync({
							category: "monitoring",
							entries: [
								{ key: "chartsRefreshSec", value: Number(monitoring.chartsRefreshSec) },
								{ key: "retentionDays", value: Number(monitoring.retentionDays) },
							],
						})
						break
					case "auth":
						await saveMutation.mutateAsync({
							category: "auth",
							entries: [
								{ key: "mode", value: auth.mode },
								{ key: "google", value: auth.google },
								{ key: "github", value: auth.github },
								{ key: "enforceMfa", value: auth.enforceMfa },
								{ key: "authenticators", value: auth.authenticators },
							],
						})
						break
					case "docs":
						await saveMutation.mutateAsync({
							category: "docs",
							entries: [{ key: "showPublicDocsLink", value: docs.showPublicDocsLink }],
						})
						break
					case "security":
						await saveMutation.mutateAsync({
							category: "security",
							entries: [
								{ key: "sessionMaxAgeMin", value: Number(security.sessionMaxAgeMin) },
								{ key: "requireEmailVerification", value: Boolean(security.requireEmailVerification) },
								{ key: "loginIpWindowSec", value: Number(security.loginIpWindowSec) },
								{ key: "loginIpLimit", value: Number(security.loginIpLimit) },
								{ key: "loginLockWindowSec", value: Number(security.loginLockWindowSec) },
								{ key: "loginLockThreshold", value: Number(security.loginLockThreshold) },
								{ key: "loginLockDurationMin", value: Number(security.loginLockDurationMin) },
								{ key: "passwordHistoryLimit", value: Number(security.passwordHistoryLimit) },
							],
						})
						break
				}
			} finally {
				setSaving(null)
			}
		},
		[auth, docs, general, monitoring, saveMutation, security]
	)

	if (!canManageNavigation) {
		return (
			<div className="p-6">
				<div className="flex items-center gap-2 text-red-600 dark:text-red-400">
					<ShieldAlert className="h-5 w-5" />
					Access denied
				</div>
				<p className="text-sm text-muted-foreground mt-2">
					Only administrators can manage the navigation menus.
				</p>
			</div>
		)
	}

	const menuError = settingsMenuQuery.isError ? settingsMenuQuery.error : null

	let sectionContent: React.ReactNode
	if (settingsLoading) {
		sectionContent = <p className="text-sm text-muted-foreground">Loading settings…</p>
	} else if (!activeCategory || !activeNavItem) {
		sectionContent = (
			<div className="rounded border border-dashed p-6 text-center text-sm text-muted-foreground">
				Select a settings section to get started.
			</div>
		)
	} else {
		switch (activeCategory) {
			case "general":
				sectionContent = (
					<GeneralSettingsSection
						state={general}
						setState={setGeneral}
						onSave={() => saveCategory("general")}
						saving={saving === "general"}
					/>
				)
				break
			case "monitoring":
				sectionContent = (
					<MonitoringSettingsSection
						state={monitoring}
						setState={setMonitoring}
						onSave={() => saveCategory("monitoring")}
						saving={saving === "monitoring"}
					/>
				)
				break
			case "auth":
				sectionContent = (
					<AuthSettingsSection
						state={auth}
						setState={setAuthSettings}
						onSave={() => saveCategory("auth")}
						saving={saving === "auth"}
					/>
				)
				break
			case "docs":
				sectionContent = (
					<DocsSettingsSection
						state={docs}
						setState={setDocs}
						onSave={() => saveCategory("docs")}
						saving={saving === "docs"}
					/>
				)
				break
			case "security":
				sectionContent = (
					<SecuritySettingsSection
						state={security}
						setState={setSecurity}
						onSave={() => saveCategory("security")}
						saving={saving === "security"}
					/>
				)
				break
			default:
				sectionContent = (
					<div className="rounded border border-dashed p-6 text-center text-sm text-muted-foreground">
						Select a settings section to get started.
					</div>
				)
		}

	}

	const routeIsActive = Boolean(activeNavItem?.route && matchesRoute(location.pathname, activeNavItem.route))
	const hasOutlet = Boolean(outlet)
	const shouldShowRouteContent = hasOutlet || routeIsActive
	const routeContent = shouldShowRouteContent
		? outlet ?? (
			<div className="rounded border border-dashed p-6 text-center text-sm text-muted-foreground">
				Section content is loading…
			</div>
		)
		: null
	const resolvedSectionContent = routeContent ?? sectionContent

	return (
		<div className="p-6 space-y-6">
			<div>
				<h1 className="text-2xl font-semibold">Admin Settings</h1>
				<p className="text-sm text-muted-foreground mt-1">
					Configure platform-wide administrative options.
				</p>
			</div>

			{menuError ? (
				<Alert variant="destructive">
					<AlertTitle>Unable to load navigation</AlertTitle>
					<AlertDescription>{menuError instanceof Error ? menuError.message : "An unexpected error occurred."}</AlertDescription>
				</Alert>
			) : null}

			{settingsError ? (
				<Alert variant="destructive">
					<AlertTitle>Unable to load settings</AlertTitle>
					<AlertDescription>
						{settingsError instanceof Error ? settingsError.message : "An unexpected error occurred while loading settings."}
					</AlertDescription>
				</Alert>
			) : null}

			<div className="flex flex-col lg:flex-row gap-6">
				<aside className="w-full lg:w-64 lg:sticky lg:top-4 h-fit">
					<nav className="rounded border p-3 space-y-3">
						<div className="text-xs uppercase text-muted-foreground px-1">Settings</div>
						<div className="px-1">
							<Input
								value={filter}
								onChange={handleFilterChange}
								placeholder="Search sections"
								className="h-9"
							/>
						</div>
						{settingsMenuQuery.isLoading ? (
							<p className="text-sm text-muted-foreground px-1">Loading sections…</p>
						) : filteredSectionGroups.length ? (
							filteredSectionGroups.map((group) => (
								<div key={group.id} className="space-y-2">
									<div className="px-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
										{group.title}
									</div>
									<ul className="space-y-1">
										{group.items.map((item) => (
											<li key={item.id}>
												{item.category ? (
													<button
														type="button"
														onClick={() => handleSelectNavItem(item)}
														className={cn(
															"flex w-full items-center gap-2 rounded px-2 py-1 text-sm transition",
															item.id === activeNavItem?.id
																? "bg-accent text-accent-foreground"
																: "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
														)}
														ref={item.id === activeNavItem?.id ? activeSectionRef : undefined}
													>
														{item.icon ? <item.icon className="size-4" /> : null}
														<span className="flex-1 truncate">{item.title}</span>
													</button>
												) : item.route ? (
													<Link
														to={item.route}
														className={cn(
															"flex w-full items-center gap-2 rounded px-2 py-1 text-sm transition",
															matchesRoute(location.pathname, item.route)
																? "bg-accent text-accent-foreground"
																: "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
														)}
													>
														{item.icon ? <item.icon className="size-4" /> : null}
														<span className="flex-1 truncate">{item.title}</span>
													</Link>
												) : (
													<div className="flex items-center justify-between rounded px-2 py-1 text-sm text-muted-foreground/70">
														<span className="truncate">{item.title}</span>
														<span className="rounded-full border px-2 text-[10px] uppercase tracking-wide">Soon</span>
													</div>
												)}
											</li>
										))}
									</ul>
								</div>
							))
						) : hasFilter ? (
							<p className="text-sm text-muted-foreground px-1">No sections match "{filter.trim()}".</p>
						) : (
							<p className="text-sm text-muted-foreground px-1">No settings sections are available.</p>
						)}
					</nav>
				</aside>

				<section className="flex-1 space-y-6">
					<div>
						<h2 className="text-xl font-semibold">{activeNavItem?.title ?? "Settings overview"}</h2>
						<p className="text-sm text-muted-foreground">
							{activeNavItem ? `Manage ${activeNavItem.parentTitle.toLowerCase()} preferences.` : "Pick a section from the navigation to begin."}
						</p>
					</div>
					{resolvedSectionContent}
				</section>
			</div>
		</div>
	)
}
