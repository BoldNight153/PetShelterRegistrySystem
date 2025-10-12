import { Outlet, useLocation, useNavigate } from "react-router-dom"
import * as React from "react"
import { useEffect, useRef, useState } from "react"
import { useAuth } from "@/lib/auth-context"
import TeamSwitcher from "@/components/team-switcher"
import NavUser from "@/components/nav-user"
import ThemeToggleButton from "@/components/ui/theme-toggle-button"
import { AudioWaveform, Command, GalleryVerticalEnd } from "lucide-react"
import AppSidebar from "@/components/app-sidebar"
import AuthDrawer from "@/components/auth/AuthDrawer"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Separator } from "@/components/ui/separator"
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar"
import { Toaster } from "@/components/ui/sonner"
import { getAuthDrawerVariant } from "@/lib/settings"

export default function RootLayout() {
  const location = useLocation()
  const navigate = useNavigate()
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [drawerView, setDrawerView] = useState<"login" | "register">("login")
  const initialPathRef = useRef<string | null>(null)
  const prevPathRef = useRef<string | null>(null)
  const successCloseRef = useRef(false)
  const { authenticated } = useAuth()
  const isAuthPath = (p: string) => ["/login", "/register", "/signup"].includes(p)

  // Initialize initial path once
  if (initialPathRef.current === null) {
    initialPathRef.current = location.pathname
  }

  // Option A-2: Always open drawer on auth routes (keep URL). If authenticated, redirect to dashboard.
  useEffect(() => {
    if (isAuthPath(location.pathname)) {
      // If already authenticated, send to dashboard
      if (authenticated) {
        navigate("/dashboard", { replace: true })
        return
      }
      const view = location.pathname === "/login" ? "login" : "register"
      setDrawerView(view)
      setDrawerOpen(true)
      // Do not change URL; keep it for intent and crawlers
    } else {
      // Track the last non-auth path for closing behavior
      prevPathRef.current = location.pathname
    }
  }, [location.pathname, authenticated, navigate])

  // Body scroll lock while drawer is open (accessibility/UX refinement)
  useEffect(() => {
    const prev = document.body.style.overflow
    if (drawerOpen) {
      document.body.style.overflow = "hidden"
    } else {
      document.body.style.overflow = prev
    }
    return () => {
      document.body.style.overflow = prev
    }
  }, [drawerOpen])

  // Compute a safe returnTo from query string
  const searchParams = new URLSearchParams(location.search)
  const rawReturnTo = searchParams.get("returnTo") || undefined
  const safeReturnTo = rawReturnTo && rawReturnTo.startsWith("/") && !rawReturnTo.startsWith("//") ? rawReturnTo : undefined

  const teams = [
    { name: "Acme Inc", logo: GalleryVerticalEnd, plan: "Enterprise" },
    { name: "Acme Corp.", logo: AudioWaveform, plan: "Startup" },
    { name: "Evil Corp.", logo: Command, plan: "Free" },
  ]
  return (
    <SidebarProvider>
      <AppSidebar />
  <SidebarInset className="flex flex-1 flex-col min-h-[100dvh]">
  <HeaderBar teams={teams} />
        {/* Toasts: top-right within the app content area */}
        <Toaster position="top-right" richColors closeButton />
        {/* Global route-aware Auth Drawer */}
        <AuthDrawer
          open={drawerOpen}
          onOpenChange={(o) => {
            setDrawerOpen(o)
            // If closing and we're on an auth URL, navigate back to last non-auth route unless this close was a success
            if (!o && ["/login", "/register", "/signup"].includes(location.pathname)) {
              if (successCloseRef.current) {
                successCloseRef.current = false
                return
              }
              navigate("/", { replace: true })
            }
          }}
          initialView={drawerView}
          drawerVariant={getAuthDrawerVariant()}
          onSuccess={() => {
            successCloseRef.current = true
            setDrawerOpen(false)
            // After success, prefer returnTo; else go to dashboard
            if (safeReturnTo) {
              navigate(safeReturnTo, { replace: true })
            } else {
              navigate("/dashboard", { replace: true })
            }
          }}
        />
        <main className="relative flex min-h-0 flex-1 flex-col p-4 pt-0 w-full">
          {/* Fixed-height viewport area under sticky header; wrapper corners always visible */}
          <div className="flex-1 min-h-0 overflow-hidden">
            <div className="flex flex-1 flex-col rounded-xl border bg-sidebar">
              {/* Scroll inside the wrapper so its rounded corners always remain visible */}
              <div className="flex-1 overflow-auto p-4">
                <div id="content-root">
                  {/* When on an auth route and drawer is open, hide route content to avoid duplicate form fields */}
                  {!(drawerOpen && isAuthPath(location.pathname)) && <Outlet />}
                </div>
              </div>
            </div>
          </div>
          {/* Overlay portal root: keep it non-interactive until something mounts inside it */}
          <div id="content-overlay-root" className="absolute inset-0 z-50 w-full pointer-events-none" aria-hidden="true" />
        </main>
      </SidebarInset>
    </SidebarProvider>
  )
}

function HeaderBar({ teams }: { teams: Array<{ name: string; logo: any; plan: string }> }) {
  const { authenticated } = useAuth()
  const location = useLocation()

  // Build simple, route-aware breadcrumbs
  const path = location.pathname.replace(/\/+$/, "") || "/"
  const segments = path === "/" ? [] : path.split("/").filter(Boolean)
  const titleMap: Record<string, string> = {
    "/": "Home",
    "/docs": "Docs",
    "/dashboard": "Dashboard",
    "/login": "Sign in",
    "/register": "Create account",
    "/signup": "Create account",
  }
  const humanize = (s: string) =>
    decodeURIComponent(s)
      .replace(/-/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase())

  const crumbs = (() => {
    const items: Array<{ href: string; label: string }> = []
    // Always include home crumb as the first item
    items.push({ href: "/", label: titleMap["/"] })
    let acc = ""
    for (const seg of segments) {
      acc += `/${seg}`
      const label = titleMap[acc] ?? humanize(seg)
      items.push({ href: acc, label })
    }
    return items
  })()
  return (
    <header className="sticky top-0 z-50 flex h-16 shrink-0 items-center justify-between gap-2 border-b border-border bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60 transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-12">
      <div className="flex items-center gap-2 px-4">
        <SidebarTrigger className="-ml-1" />
        <Separator orientation="vertical" className="mr-2 data-[orientation=vertical]:h-4" />
        {/* Mobile-only: show Team Switcher on small screens, hide on md and up */}
        <div className="md:hidden">
          <TeamSwitcher teams={teams} />
        </div>
        <Breadcrumb>
          <BreadcrumbList>
            {crumbs.map((c, idx) => {
              const isLast = idx === crumbs.length - 1
              return (
                <React.Fragment key={c.href}>
                  <BreadcrumbItem className={idx === 0 ? "hidden md:block" : undefined}>
                    {isLast ? (
                      <BreadcrumbPage>{c.label}</BreadcrumbPage>
                    ) : (
                      <BreadcrumbLink href={c.href}>{c.label}</BreadcrumbLink>
                    )}
                  </BreadcrumbItem>
                  {!isLast && (
                    <BreadcrumbSeparator className={idx === 0 ? "hidden md:block" : undefined} />
                  )}
                </React.Fragment>
              )
            })}
          </BreadcrumbList>
        </Breadcrumb>
      </div>
      <div className="px-3 flex items-center gap-2">
        {/* When logged out, show single-button theme toggle + Login | Register inline */}
  {!authenticated && <ThemeToggleButton />}
  <NavUser />
      </div>
    </header>
  )
}
