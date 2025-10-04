// React import unnecessary with the new JSX transform
import { useEffect, useMemo, useRef, useState } from "react"
import {
  ChevronsUpDown,
  LogOut,
  Sparkles,
  ServerCrash,
  Server,
  RefreshCcw,
  Settings2,
} from "lucide-react"

import {
  Avatar,
  AvatarFallback,
  AvatarImage,
} from "@/components/ui/avatar"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar"
import { ThemeToggle } from "@/components/ui/theme-toggle"

export default function NavUser({
  user,
}: {
  user: {
    name: string
    email: string
    avatar: string
  }
}) {
  const { isMobile } = useSidebar()

  // API status indicator state
  type ApiState = "checking" | "online" | "offline"
  const [apiState, setApiState] = useState<ApiState>("checking")
  const [latencyMs, setLatencyMs] = useState<number | null>(null)
  const controllerRef = useRef<AbortController | null>(null)

  const checkHealth = async () => {
    try {
      controllerRef.current?.abort()
      const ctl = new AbortController()
      controllerRef.current = ctl
      setApiState("checking")
      const started = performance.now()
      // Hit the dev proxy which forwards to backend http://localhost:4000/health
      const res = await fetch("/health", { signal: ctl.signal, cache: "no-store" })
      const elapsed = Math.max(0, performance.now() - started)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setLatencyMs(Math.round(elapsed))
      setApiState("online")
    } catch (_err) {
      setApiState("offline")
      setLatencyMs(null)
    }
  }

  useEffect(() => {
    let timer: any
    // Initial check soon after mount
    checkHealth()
    // Poll every 30s to keep it up to date during dev sessions
    timer = setInterval(checkHealth, 30000)
    return () => {
      clearInterval(timer)
      controllerRef.current?.abort()
    }
  }, [])

  const statusDisplay = useMemo(() => {
    const dotClass =
      apiState === "online"
        ? "bg-emerald-500"
        : apiState === "offline"
        ? "bg-rose-500"
        : "bg-amber-500"
    const label =
      apiState === "online"
        ? `Online${latencyMs != null ? ` • ${latencyMs}ms` : ""}`
        : apiState === "offline"
        ? "Offline"
        : "Checking…"
    const Icon = apiState === "online" ? Server : apiState === "offline" ? ServerCrash : RefreshCcw
    return { dotClass, label, Icon }
  }, [apiState, latencyMs])

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton
              aria-label="User menu"
              size="lg"
              className="px-2 sm:px-3 data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
            >
              <Avatar className="h-8 w-8 rounded-lg">
                <AvatarImage src={user.avatar} alt={user.name} />
                <AvatarFallback className="rounded-lg">CN</AvatarFallback>
              </Avatar>
              <div className="hidden sm:grid flex-1 text-left text-sm leading-tight">
                <span className="truncate font-medium">{user.name}</span>
                <span className="truncate text-xs">{user.email}</span>
              </div>
              <ChevronsUpDown className="ml-auto size-4 hidden sm:block" />
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
                  <AvatarImage src={user.avatar} alt={user.name} />
                  <AvatarFallback className="rounded-lg">CN</AvatarFallback>
                </Avatar>
                <div className="grid flex-1 text-left text-sm leading-tight">
                  <span className="truncate font-medium">{user.name}</span>
                  <span className="truncate text-xs">{user.email}</span>
                </div>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuGroup>
              <DropdownMenuItem>
                <Sparkles />
                Upgrade to Pro
              </DropdownMenuItem>
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            {/* Settings (replaces Account/Billing/Notifications) */}
            <DropdownMenuGroup>
              <DropdownMenuItem>
                <Settings2 />
                Settings
              </DropdownMenuItem>
            </DropdownMenuGroup>
            {/* API status moved to sit directly above Theme */}
            <DropdownMenuSeparator />
            <DropdownMenuGroup>
              <DropdownMenuItem onClick={(e) => { e.preventDefault(); checkHealth() }} className="gap-2">
                <span className={`inline-block size-2 rounded-full ${statusDisplay.dotClass}`} />
                {(() => { const Icon = statusDisplay.Icon; return <Icon className="size-4" /> })()}
                <span className="flex-1">API status</span>
                <span className="text-xs opacity-70">{statusDisplay.label}</span>
              </DropdownMenuItem>
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuLabel>Theme</DropdownMenuLabel>
            <div className="px-2 py-1.5">
              <ThemeToggle />
            </div>
            <DropdownMenuSeparator />
            <DropdownMenuItem>
              <LogOut />
              Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  )
}
