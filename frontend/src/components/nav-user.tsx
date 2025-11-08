import * as React from "react"
import { BadgeCheck, Bell, ChevronsUpDown, CreditCard, LogOut } from "lucide-react"

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

type NavUserProps = {
  placement?: "header" | "sidebar"
}

export default function NavUser({ placement = "header" }: NavUserProps) {
  const { isMobile, state } = useSidebar()
  const { logout, authenticated, user } = useAuth()
  const [drawerOpen, setDrawerOpen] = React.useState(false)
  const [drawerView, setDrawerView] = React.useState<"login" | "register">("login")

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
              <DropdownMenuItem>
                <BadgeCheck />
                Account
              </DropdownMenuItem>
              <DropdownMenuItem>
                <CreditCard />
                Billing
              </DropdownMenuItem>
              <DropdownMenuItem>
                <Bell />
                Notifications
              </DropdownMenuItem>
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
