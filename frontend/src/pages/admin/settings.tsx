import * as React from "react"
import { ShieldAlert } from "lucide-react"
import type { LucideIcon } from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"
import { useAuth } from "@/lib/auth-context"
import { filterNavigationTree, resolveIcon } from "@/lib/navigation-map"
import { useAdminSettings, useSaveAdminSettings } from "@/services/hooks/admin"
import { useNavigationMenu } from "@/services/hooks/navigation"
import type { NavigationMenu, NavigationMenuItem } from "@/services/interfaces/navigation.interface"
import { useSearchParams } from "react-router-dom"

type SettingsCategory = "general" | "monitoring" | "auth" | "docs" | "security"

type SectionNavItem = {
	id: string
	title: string
	category?: SettingsCategory
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

type AuthState = {
	mode: "session" | "jwt"
	google: boolean
	github: boolean
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
			items.push({
				id: child.id,
				title: child.title,
				category,
				icon: resolveIcon(child.icon ?? undefined),
				comingSoon: !category,
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
	return (
		<div className="space-y-4">
			<div className="rounded border p-4 space-y-4">
				<div>
					<label htmlFor="auth-mode" className="block text-sm font-medium">Auth mode</label>
					<select
						id="auth-mode"
						aria-label="Authentication mode"
						className="mt-1 w-60 rounded-md border px-3 py-2 bg-background"
						value={state.mode}
						onChange={(event) => setState((prev) => ({ ...prev, mode: event.target.value as AuthState["mode"] }))}
					>
						<option value="session">session</option>
						<option value="jwt">jwt</option>
					</select>
					<p className="text-xs text-muted-foreground mt-1">Switch between server sessions and stateless JWT cookies.</p>
				</div>
				<div>
					<label className="block text-sm font-medium">OAuth providers</label>
					<div className="mt-1 grid grid-cols-1 sm:grid-cols-2 gap-3">
						<label className="flex items-center gap-2 text-sm">
							<input
								type="checkbox"
								className="accent-foreground"
								checked={state.google}
								onChange={(event) => setState((prev) => ({ ...prev, google: event.target.checked }))}
							/>
							Google
						</label>
						<label className="flex items-center gap-2 text-sm">
							<input
								type="checkbox"
								className="accent-foreground"
								checked={state.github}
								onChange={(event) => setState((prev) => ({ ...prev, github: event.target.checked }))}
							/>
							GitHub
						</label>
					</div>
					<p className="text-xs text-muted-foreground mt-1">Enable only providers with valid credentials configured.</p>
				</div>
				<div className="pt-2">
					<Button type="button" size="sm" onClick={() => { void onSave() }} disabled={saving}>
						{saving ? "Saving…" : "Save Authentication"}
					</Button>
				</div>
			</div>
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
	const [searchParams, setSearchParams] = useSearchParams()
	const sectionParam = searchParams.get("section")

	const [general, setGeneral] = React.useState<GeneralState>({ appName: "Pet Shelter Registry", supportEmail: "" })
	const [monitoring, setMonitoring] = React.useState<MonitoringState>({ chartsRefreshSec: 15, retentionDays: 7 })
	const [auth, setAuthSettings] = React.useState<AuthState>({ mode: "session", google: false, github: false })
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
			setAuthSettings({
				mode: s.auth.mode === "jwt" ? "jwt" : "session",
				google: Boolean(s.auth.google),
				github: Boolean(s.auth.github),
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

	const [activeCategory, setActiveCategory] = React.useState<SettingsCategory | null>(null)

	React.useEffect(() => {
		const firstCategory = candidateCategoryItems[0]?.category ?? null
		if (!candidateCategoryItems.length) {
			if (activeCategory !== null) {
				setActiveCategory(null)
			}
			return
		}
		if (!activeCategory && firstCategory) {
			setActiveCategory(firstCategory)
			return
		}
		if (activeCategory && !candidateCategoryItems.some((item) => item.category === activeCategory)) {
			if (firstCategory && firstCategory !== activeCategory) {
				setActiveCategory(firstCategory)
			}
		}
	}, [candidateCategoryItems, activeCategory])

	React.useEffect(() => {
		if (!sectionParam) return
		if (!isSettingsCategory(sectionParam)) return
		const match = categoryItems.find((item) => item.category === sectionParam)
		if (!match) return
		if (activeCategory === sectionParam) return
		setActiveCategory(sectionParam)
	}, [sectionParam, categoryItems, activeCategory])

	React.useEffect(() => {
		if (activeCategory) {
			commitSearchParams((params) => {
				params.set("section", activeCategory)
			})
		} else {
			commitSearchParams((params) => {
				params.delete("section")
			})
		}
	}, [activeCategory, commitSearchParams])

	React.useEffect(() => {
		if (!sectionParam) return
		if (activeCategory !== sectionParam) return
		if (!activeSectionRef.current) return
		activeSectionRef.current.scrollIntoView({ behavior: "smooth", block: "nearest" })
	}, [sectionParam, activeCategory])

	const activeNavItem = React.useMemo(
		() => categoryItems.find((item) => item.category === activeCategory) ?? null,
		[categoryItems, activeCategory]
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
														onClick={() => setActiveCategory(item.category!)}
														className={cn(
															"flex w-full items-center gap-2 rounded px-2 py-1 text-sm transition",
															item.category === activeCategory
																? "bg-accent text-accent-foreground"
																: "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
														)}
														ref={item.category === activeCategory ? activeSectionRef : undefined}
													>
														{item.icon ? <item.icon className="size-4" /> : null}
														<span className="flex-1 truncate">{item.title}</span>
													</button>
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
					{sectionContent}
				</section>
			</div>
		</div>
	)
}
