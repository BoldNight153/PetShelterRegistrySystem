import * as React from "react"
import * as ToggleGroup from "@radix-ui/react-toggle-group"
import { Sun, Moon, Monitor } from "lucide-react"

type Mode = "system" | "light" | "dark"

function applyTheme(mode: Mode) {
  const html = document.documentElement
  let effective: "light" | "dark"
  if (mode === "system") {
    const mm = window.matchMedia("(prefers-color-scheme: dark)")
    effective = mm.matches ? "dark" : "light"
  } else {
    effective = mode
  }
  html.classList.toggle("dark", effective === "dark")
  html.setAttribute("data-theme", effective)
  try { localStorage.setItem("theme", mode) } catch {}
  try { window.dispatchEvent(new CustomEvent("themechange", { detail: { mode: effective } })) } catch {}
}

export function ThemeToggleGroup() {
  const [mode, setMode] = React.useState<Mode>(() => {
    if (typeof window === "undefined") return "system"
    try {
      const stored = (localStorage.getItem("theme") || "system") as Mode
      return stored === "light" || stored === "dark" || stored === "system" ? stored : "system"
    } catch { return "system" }
  })

  // Apply immediately and respond to system changes only when in system mode
  React.useEffect(() => {
    if (typeof document === "undefined") return
    applyTheme(mode)
    if (mode === "system") {
      const mm = window.matchMedia("(prefers-color-scheme: dark)")
      const handler = () => applyTheme("system")
      try { mm.addEventListener("change", handler) } catch { mm.addListener(handler) }
      return () => { try { mm.removeEventListener("change", handler) } catch { mm.removeListener(handler) } }
    }
  }, [mode])

  return (
    <ToggleGroup.Root
      type="single"
      value={mode}
      onValueChange={(v) => v && setMode(v as Mode)}
      aria-label="Theme"
      className="flex items-center gap-1 rounded-md border px-1 py-0.5 text-xs"
    >
      <ToggleGroup.Item value="light" className="px-2 py-1 data-[state=on]:bg-accent rounded" aria-label="Light">
        <Sun className="h-4 w-4" />
      </ToggleGroup.Item>
      <ToggleGroup.Item value="dark" className="px-2 py-1 data-[state=on]:bg-accent rounded" aria-label="Dark">
        <Moon className="h-4 w-4" />
      </ToggleGroup.Item>
      <ToggleGroup.Item value="system" className="px-2 py-1 data-[state=on]:bg-accent rounded" aria-label="System">
        <Monitor className="h-4 w-4" />
      </ToggleGroup.Item>
    </ToggleGroup.Root>
  )
}

export default ThemeToggleGroup
