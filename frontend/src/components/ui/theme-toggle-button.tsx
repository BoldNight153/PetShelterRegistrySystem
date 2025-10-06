import * as React from "react"
import { Sun, Moon, Monitor } from "lucide-react"

type Mode = "system" | "light" | "dark"

function computeEffective(mode: Mode): "light" | "dark" {
  if (mode === "system") {
    const mm = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)")
    return mm && mm.matches ? "dark" : "light"
  }
  return mode
}

function apply(mode: Mode) {
  const html = document.documentElement
  const eff = computeEffective(mode)
  html.classList.toggle("dark", eff === "dark")
  html.setAttribute("data-theme", eff)
  try { localStorage.setItem("theme", mode) } catch {}
  try { window.dispatchEvent(new CustomEvent("themechange", { detail: { mode: eff } })) } catch {}
}

export function ThemeToggleButton() {
  const [mode, setMode] = React.useState<Mode>(() => {
    if (typeof window === "undefined") return "system"
    try {
      const stored = (localStorage.getItem("theme") || "system") as Mode
      return stored === "system" || stored === "light" || stored === "dark" ? stored : "system"
    } catch { return "system" }
  })

  React.useEffect(() => {
    apply(mode)
    if (mode === "system") {
      const mm = window.matchMedia("(prefers-color-scheme: dark)")
      const handler = () => apply("system")
      try { mm.addEventListener("change", handler) } catch { mm.addListener(handler) }
      return () => { try { mm.removeEventListener("change", handler) } catch { mm.removeListener(handler) } }
    }
  }, [mode])

  const cycle = () => {
    setMode((prev) => (prev === "system" ? "light" : prev === "light" ? "dark" : "system"))
  }

  const eff = computeEffective(mode)
  const Icon = mode === "system" ? Monitor : eff === "dark" ? Moon : Sun
  const label = `Theme: ${mode}`

  return (
    <button onClick={cycle} aria-label={label} title={label} className="inline-flex items-center justify-center rounded-md border px-2 py-1">
      <Icon className="h-4 w-4" />
    </button>
  )
}

export default ThemeToggleButton
