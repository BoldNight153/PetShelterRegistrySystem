"use client"

import { useEffect, useMemo, useState } from "react"
import {
  AudioWaveform,
  BookOpen,
  Command,
  Folder,
  GalleryVerticalEnd,
  Home,
  LogIn,
  UserPlus,
} from "lucide-react"

import NavMain, { type NavMainItem } from "@/components/nav-main"
import { NavProjects } from "@/components/nav-projects"
import NavUser from "@/components/nav-user"
import TeamSwitcher from "@/components/team-switcher"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
} from "@/components/ui/sidebar"
import { mapMenuToNavMain, mapToProjectNav } from "@/lib/navigation-map"
import { useAuth } from "@/lib/auth-context"
import { useServices } from "@/services/hooks"
import type { NavigationMenu } from "@/services/interfaces/navigation.interface"

type LoadState = "idle" | "loading" | "ready" | "error"

type SidebarState = {
  status: LoadState
  menu: NavigationMenu | null
  error?: string
}

const DEFAULT_MENU_NAME = "main"

const DEFAULT_TEAMS = [
  { name: "Shelter Operations", logo: GalleryVerticalEnd, plan: "Admin" },
  { name: "Clinic", logo: AudioWaveform, plan: "Medical" },
  { name: "Outreach", logo: Command, plan: "Community" },
]

const PUBLIC_NAV_ITEMS: NavMainItem[] = [
  {
    title: "Overview",
    url: "/",
    icon: Home,
  },
  {
    title: "Documentation",
    url: "/docs",
    icon: BookOpen,
    items: [
      { title: "API explorer", url: "/docs" },
      { title: "Pets API intro", url: "/docs/api/pets/introduction" },
      { title: "Auth quickstart", url: "/docs/api/auth/get-started" },
    ],
  },
  {
    title: "Log in",
    url: "/login",
    icon: LogIn,
  },
  {
    title: "Sign up",
    url: "/signup",
    icon: UserPlus,
  },
]

export default function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const { navigation } = useServices()
  const { user } = useAuth()
  const [state, setState] = useState<SidebarState>({ status: "idle", menu: null })
  const [reloadCount, setReloadCount] = useState(0)

  const isAuthenticated = Boolean(user?.id)

  const menuName = (typeof import.meta !== "undefined" && import.meta.env?.VITE_APP_SIDEBAR_MENU) || DEFAULT_MENU_NAME
  const authSignature = `${user?.id ?? "guest"}|${(user?.roles ?? []).join(",")}`

  useEffect(() => {
    if (!isAuthenticated) {
      setState({ status: "ready", menu: null })
      return
    }
    let cancelled = false
    setState((prev) => ({ ...prev, status: "loading", error: undefined, menu: prev.menu }))
    ;(async () => {
      try {
        const menu = await navigation.getMenu(menuName)
        if (cancelled) return
        if (!menu) {
          setState({ status: "ready", menu: null })
          return
        }
        setState({ status: "ready", menu })
      } catch (err) {
        if (cancelled) return
        const message = err instanceof Error ? err.message : "Failed to load navigation menu"
        setState({ status: "error", menu: null, error: message })
      }
    })()
    return () => {
      cancelled = true
    }
  }, [authSignature, isAuthenticated, menuName, navigation, reloadCount])

  const { navItems, projectItems } = useMemo(() => {
    const menuItems = state.menu?.items ?? []
    const projectIndex = menuItems.findIndex((item) => item.title?.toLowerCase() === "projects")
    const projectSection = projectIndex >= 0 ? menuItems[projectIndex] : undefined
    const filtered = projectIndex >= 0 ? menuItems.filter((_, index) => index !== projectIndex) : menuItems
    return {
      navItems: mapMenuToNavMain(filtered),
      projectItems: mapToProjectNav(projectSection?.children ?? [], Folder),
    }
  }, [state.menu])

  const effectiveNavItems = isAuthenticated ? navItems : PUBLIC_NAV_ITEMS
  const showNavFallback = isAuthenticated && navItems.length === 0

  const loadingMessage =
    state.status === "loading"
      ? "Loading navigation…"
      : state.status === "error"
        ? state.error ?? "Unable to load navigation"
        : "No menu configured"

  return (
    <Sidebar collapsible="icon" {...props}>
      <SidebarHeader>
  <TeamSwitcher teams={DEFAULT_TEAMS} />
      </SidebarHeader>
      <SidebarContent>
        {effectiveNavItems.length > 0 && (
          <NavMain label={state.menu?.title ?? "Navigation"} items={effectiveNavItems} />
        )}
        {showNavFallback && (
          <SidebarGroup>
            <SidebarGroupLabel>Navigation</SidebarGroupLabel>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton
                  type="button"
                  disabled={state.status === "loading"}
                  onClick={() => setReloadCount((count) => count + 1)}
                  className="text-xs"
                >
                  <span className="text-left">
                    {loadingMessage}
                    {state.status === "error" ? " — click to retry" : ""}
                  </span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroup>
        )}
        {isAuthenticated && projectItems.length > 0 && <NavProjects projects={projectItems} />}
      </SidebarContent>
      <SidebarFooter>
        <NavUser placement="sidebar" />
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  )
}
