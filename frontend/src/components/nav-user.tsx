import * as React from "react"
import { BadgeCheck, Bell, ChevronsUpDown, CreditCard, ExternalLink, LogOut, Settings2 } from "lucide-react"

import type { LucideIcon } from "lucide-react"

import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem, useSidebar } from "@/components/ui/sidebar"
import ThemeToggleGroup from "@/components/ui/theme-toggle-group"
import { useAuth } from '@/lib/auth-context'
// no direct Links here; we open an Auth drawer
import AuthDrawer from "@/components/auth/AuthDrawer"
import { useNavigationMenu } from "@/services/hooks/navigation"
import { filterNavigationTree, resolveIcon } from "@/lib/navigation-map"
import { useNavigate } from "react-router-dom"
import type { NavigationMenuItem } from "@/services/interfaces/navigation.interface"

type SettingsCategory = "general" | "monitoring" | "auth" | "docs" | "security"

const SUPPORTED_SETTINGS_CATEGORIES: SettingsCategory[] = ["general", "monitoring", "auth", "docs", "security"]

type QuickLink = {
  title: string
  url: string
  icon?: LucideIcon
  external?: boolean
  target?: string | null
  section?: SettingsCategory
  searchLabel?: string
}

function userHasAccess(meta: unknown, roles: string[]): boolean {
  if (!meta || typeof meta !== "object") return true
  const record = meta as Record<string, unknown>
  const requiresRoles = Array.isArray(record.requiresRoles) ? record.requiresRoles.map(String) : null
  if (requiresRoles && requiresRoles.length > 0) {
    const allowed = requiresRoles.some((role) => roles.includes(role))
    if (!allowed) return false
  }
  return true
}

function parseSettingsCategory(meta: unknown): SettingsCategory | null {
  if (!meta || typeof meta !== "object") return null
  const record = meta as Record<string, unknown>
  const value = record.settingsCategory
  if (typeof value !== "string") return null
  return SUPPORTED_SETTINGS_CATEGORIES.includes(value as SettingsCategory) ? (value as SettingsCategory) : null
}

type NavUserProps = {
  placement?: "header" | "sidebar"
}

export default function NavUser({ placement = "header" }: NavUserProps) {
  const { isMobile, state } = useSidebar()
  const { logout, authenticated, user } = useAuth()
  const navigate = useNavigate()
  const { data: settingsMenu } = useNavigationMenu("settings_main")
  const [drawerOpen, setDrawerOpen] = React.useState(false)
  const [drawerView, setDrawerView] = React.useState<"login" | "register">("login")

  const userRoles = React.useMemo(() => user?.roles ?? [], [user])

  const quickLinks: QuickLink[] = React.useMemo(() => {
    if (!settingsMenu?.items || settingsMenu.items.length === 0) return []

    const visibleItems = filterNavigationTree(settingsMenu.items ?? [])
    const links: QuickLink[] = []

    for (const item of visibleItems) {
      if (!userHasAccess(item.meta, userRoles)) continue
      const children: NavigationMenuItem[] = item.children ? [...item.children] : []
      const eligibleChild = children.find((child) => child.url && userHasAccess(child.meta, userRoles))
      const targetNode = item.url ? item : eligibleChild
      if (!targetNode || !targetNode.url) continue

      const icon = resolveIcon(item.icon ?? targetNode.icon ?? undefined)
      const category = parseSettingsCategory(targetNode.meta)

      if (category) {
        links.push({
          title: item.title,
          url: "/settings",
          icon,
          section: category,
          searchLabel: targetNode.title ?? item.title,
        })
        continue
      }

      links.push({
        title: item.title,
        url: targetNode.url,
        icon,
        external: Boolean(targetNode.external),
        target: targetNode.target ?? null,
      })
    }

    return links
  }, [settingsMenu?.items, userRoles])

  const fallbackQuickLinks: QuickLink[] = React.useMemo(
    () => [
      { title: "Account", url: "/settings/account/profile", icon: BadgeCheck },
      { title: "Billing", url: "/settings/billing/plan", icon: CreditCard },
      { title: "Notifications", url: "/settings/account/notifications", icon: Bell },
    ],
    []
  )

  const effectiveQuickLinks = quickLinks.length > 0 ? quickLinks : fallbackQuickLinks

  const handleLink = React.useCallback(
    (link: QuickLink) => {
      if (link.external) {
        const target = link.target ?? "_blank"
        if (typeof window !== "undefined" && typeof window.open === "function") {
          window.open(link.url, target)
        }
        return
      }
      if (link.section) {
        const params = new URLSearchParams()
        params.set("section", link.section)
        if (link.searchLabel) {
          params.set("q", link.searchLabel)
        }
        navigate({ pathname: "/settings", search: `?${params.toString()}` })
        return
      }
      navigate(link.url)
    },
    [navigate]
  )

  const settingsHomeLink = React.useMemo<QuickLink>(
    () => ({ title: "Settings", url: "/settings", icon: Settings2 }),
    []
  )

  // Unauthenticated: show inline Login | Register links (works in header and sidebar footer)
  if (!authenticated || !user) {
    // In the sidebar, when collapsed to icon mode, hide the Login | Register UI entirely
    if (placement === "sidebar" && state === "collapsed") {
      return null
    }
    return (
      <>
        <div className="flex items-center gap-2 text-sm">
          <button
            className="underline"
            onClick={() => {
              setDrawerView("login")
              setDrawerOpen(true)
            }}
          >
            Log in
          </button>
          <span aria-hidden>|</span>
          <button
            className="underline"
            onClick={() => {
              setDrawerView("register")
              setDrawerOpen(true)
            }}
          >
            Register
          </button>
        </div>
        <AuthDrawer
          open={drawerOpen}
          onOpenChange={setDrawerOpen}
          initialView={drawerView}
          onSuccess={() => setDrawerOpen(false)}
        />
      </>
    )
  }

  // Condensed mode: on mobile viewports, and in collapsed sidebar icon mode show only the avatar
  const condensed = isMobile || (placement === "sidebar" && state === "collapsed")

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton
              size="lg"
              className={
                "data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground " +
                (condensed && placement === "header"
                  ? "!justify-center !gap-0 !px-2 !w-8 !h-8 rounded-lg"
                  : "")
              }
            >
              <Avatar className="h-8 w-8 rounded-lg">
                <AvatarImage src="/avatars/shadcn.jpg" alt={user.name || user.email || "User"} />
                <AvatarFallback className="rounded-lg">U</AvatarFallback>
              </Avatar>
              {!condensed && (
                <>
                  <div className="grid flex-1 text-left text-sm leading-tight">
                    <span className="truncate font-medium">{user.name || user.email || "User"}</span>
                    <span className="truncate text-xs">{user.email || ""}</span>
                  </div>
                  <ChevronsUpDown className="ml-auto size-4" />
                </>
              )}
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            className="w-[var(--radix-dropdown-menu-trigger-width)] min-w-56 rounded-lg"
            side={isMobile ? "bottom" : "right"}
            align="end"
            sideOffset={4}
          >
            <DropdownMenuLabel className="p-0 font-normal">
              <div className="flex items-center gap-2 px-1 py-1.5 text-left text-sm">
                <Avatar className="h-8 w-8 rounded-lg">
                  <AvatarImage src="/avatars/shadcn.jpg" alt={user.name || user.email || "User"} />
                  <AvatarFallback className="rounded-lg">U</AvatarFallback>
                </Avatar>
                <div className="grid flex-1 text-left text-sm leading-tight">
                  <span className="truncate font-medium">{user.name || user.email || 'User'}</span>
                  <span className="truncate text-xs">{user.email || ''}</span>
                </div>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuGroup>
              <DropdownMenuItem onSelect={() => handleLink(settingsHomeLink)}>
                <Settings2 />
                Settings
              </DropdownMenuItem>
              {effectiveQuickLinks.map((link) => {
                const Icon = link.icon ?? Settings2
                return (
                  <DropdownMenuItem key={link.title} onSelect={() => handleLink(link)}>
                    <Icon />
                    <span className="flex-1 truncate">{link.title}</span>
                    {link.external ? <ExternalLink className="size-3.5" /> : null}
                  </DropdownMenuItem>
                )
              })}
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => logout()}>
              <LogOut />
              Log out
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="flex items-center gap-2">
              <ThemeToggleGroup />
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  )
}
