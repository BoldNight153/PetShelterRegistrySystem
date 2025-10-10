import * as React from "react"
import { Drawer, DrawerContent, DrawerHeader, DrawerTitle, DrawerDescription, DrawerClose } from "@/components/ui/drawer"
import LoginForm from "@/components/auth/LoginForm"
import RegisterForm from "@/components/auth/RegisterForm"
import { Github, Mail } from "lucide-react"
import type { LucideIcon } from "lucide-react"

type AuthDrawerProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  initialView?: "login" | "register"
  onSuccess?: () => void
  drawerVariant?: "bottom" | "top" | "full"
}

export default function AuthDrawer({ open, onOpenChange, initialView = "login", onSuccess, drawerVariant = "bottom" }: AuthDrawerProps) {
  const [view, setView] = React.useState<"login" | "register">(initialView)
  React.useEffect(() => setView(initialView), [initialView])
  const [authMode, setAuthMode] = React.useState<'jwt' | 'session' | 'unknown'>('unknown')

  // Target the main content area so the drawer spans only the content, not the full viewport
  const container = React.useMemo(() => {
    if (typeof document === "undefined") return null
    return document.getElementById("content-overlay-root") as HTMLElement | null
  }, [])

  // Toggle pointer events on the portal container so it's clickable only while the drawer is open
  React.useEffect(() => {
    if (!container) return
    if (open) {
      container.style.pointerEvents = 'auto'
      container.removeAttribute('aria-hidden')
    } else {
      container.style.pointerEvents = 'none'
      container.setAttribute('aria-hidden', 'true')
    }
  }, [container, open])

  // Detect auth mode to choose OAuth endpoints
  React.useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const res = await fetch('/auth/mode', { credentials: 'include' })
        if (!res.ok) return
        const data = await res.json().catch(() => null)
        if (!cancelled) {
          const m = String(data?.authMode || '').toLowerCase()
          setAuthMode(m === 'session' ? 'session' : 'jwt')
        }
      } catch (_) { /* ignore */ }
    })()
    return () => { cancelled = true }
  }, [])

  const handleSuccess = () => {
    onOpenChange(false)
    onSuccess?.()
  }

  const OAuthButtons = () => {
    const googleHref = authMode === 'session' ? '/auth/session/google' : '/auth/oauth/google/start'
    const githubHref = authMode === 'session' ? '/auth/session/github' : '/auth/oauth/github/start'
    const buttons: Array<{ label: string; icon: LucideIcon; href: string }> = [
      { label: "Continue with Google", icon: Mail, href: googleHref },
      { label: "Continue with GitHub", icon: Github, href: githubHref },
    ]
    return (
      <div className="mt-4 flex flex-col gap-2">
        {buttons.map(b => (
          <a key={b.label} href={b.href} className="inline-flex items-center justify-center gap-2 rounded border px-4 py-2 hover:bg-accent">
            <b.icon className="h-4 w-4" />
            <span className="text-sm">{b.label}</span>
          </a>
        ))}
      </div>
    )
  }

  return (
    <Drawer open={open} onOpenChange={onOpenChange}>
  <DrawerContent className="w-full" insideContainer container={container} variant={drawerVariant}>
        <DrawerHeader>
          <DrawerTitle>{view === "login" ? "Sign in" : "Create your account"}</DrawerTitle>
          <DrawerDescription>
            {view === "login" ? "Access your account" : "Start managing pets and shelters"}
          </DrawerDescription>
        </DrawerHeader>
        <div className="p-4 flex w-full justify-center">
          <div className="w-full max-w-sm">
          {view === "login" ? (
            <LoginForm onSuccess={handleSuccess} switchToRegister={() => setView("register")} />
          ) : (
            <RegisterForm onSuccess={handleSuccess} switchToLogin={() => setView("login")} />
          )}
            <div className="my-4 flex items-center gap-2">
              <div className="h-px bg-border flex-1" />
              <span className="text-xs text-muted-foreground">or continue with</span>
              <div className="h-px bg-border flex-1" />
            </div>
            <OAuthButtons />
          </div>
        </div>
        <div className="p-4 pt-0">
          <DrawerClose asChild>
            <button className="w-full rounded-md border px-4 py-2">Close</button>
          </DrawerClose>
        </div>
      </DrawerContent>
    </Drawer>
  )
}
