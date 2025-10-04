import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react"
import { Moon, SunMedium, Laptop2 } from "lucide-react"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"

type ThemeChoice = "system" | "light" | "dark"

function getSystemPrefersDark() {
  if (typeof window === "undefined") return false
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
}

function applyTheme(choice: ThemeChoice) {
  if (typeof document === "undefined") return { applied: "light" as "light" | "dark" }
  const html = document.documentElement
  const isDark = choice === "dark" || (choice === "system" && getSystemPrefersDark())
  html.classList.toggle("dark", isDark)
  html.setAttribute("data-theme", isDark ? "dark" : "light")
  try {
    localStorage.setItem("theme", choice)
  } catch {}
  try {
    const evt = new CustomEvent("themechange", { detail: { mode: isDark ? "dark" : "light" } })
    window.dispatchEvent(evt)
  } catch {}
  return { applied: isDark ? "dark" : "light" as const }
}

function getInitialChoice(): ThemeChoice {
  if (typeof window === "undefined") return "system"
  try {
    const stored = (localStorage.getItem("theme") || "").toLowerCase()
    if (stored === "dark" || stored === "light" || stored === "system") return stored as ThemeChoice
  } catch {}
  // If html has class set, infer choice (not persisted yet)
  if (document.documentElement.classList.contains("dark")) return "dark"
  // Default to system to respect device preference
  return "system"
}

export function ThemeToggle() {
  const [choice, setChoice] = useState<ThemeChoice>(getInitialChoice)
  const mqlRef = useRef<MediaQueryList | null>(null)

  // React to changes in system preference when in system mode
  useEffect(() => {
    if (typeof window === "undefined") return
    mqlRef.current = window.matchMedia("(prefers-color-scheme: dark)")
    const onChange = () => {
      if (choice === "system") {
        applyTheme("system")
      }
    }
    const mql = mqlRef.current
    if (mql.addEventListener) mql.addEventListener("change", onChange)
    else mql.addListener(onChange)
    return () => {
      if (!mql) return
      if (mql.removeEventListener) mql.removeEventListener("change", onChange)
      else mql.removeListener(onChange)
    }
  }, [choice])

  // Apply theme when user changes choice
  useLayoutEffect(() => {
    applyTheme(choice)
  }, [choice])

  const items = useMemo(
    () => [
      { value: "light" as const, label: "Light", icon: SunMedium },
      { value: "system" as const, label: "System", icon: Laptop2 },
      { value: "dark" as const, label: "Dark", icon: Moon },
    ],
    []
  )

  return (
    <ToggleGroup
      type="single"
      value={choice}
      onValueChange={(val) => {
        if (!val) return
        setChoice(val as ThemeChoice)
      }}
      aria-label="Theme"
      variant="outline"
      size="sm"
      className="rounded-md"
    >
      {items.map(({ value, label, icon: Icon }) => (
        <ToggleGroupItem key={value} value={value} aria-label={label} title={label}>
          <Icon className="size-4" />
        </ToggleGroupItem>
      ))}
    </ToggleGroup>
  )
}

export default ThemeToggle