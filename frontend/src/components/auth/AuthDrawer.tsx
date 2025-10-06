import * as React from "react"
import { Drawer, DrawerContent, DrawerHeader, DrawerTitle, DrawerDescription, DrawerClose } from "@/components/ui/drawer"
import LoginForm from "@/components/auth/LoginForm"
import RegisterForm from "@/components/auth/RegisterForm"

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

  // Target the main content area so the drawer spans only the content, not the full viewport
  const container = React.useMemo(() => {
    if (typeof document === "undefined") return null
    return document.getElementById("content-overlay-root") as HTMLElement | null
  }, [])

  const handleSuccess = () => {
    onOpenChange(false)
    onSuccess?.()
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
