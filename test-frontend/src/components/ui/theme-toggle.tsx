import React from "react";

export function ThemeToggle() {
  const [isDark, setIsDark] = React.useState(() => {
    if (typeof window === "undefined") return false
    try {
      const stored = (localStorage.getItem("theme") || "").toLowerCase()
      if (stored === "dark") return true
      if (stored === "light") return false
    } catch {}
    if (document.documentElement.classList.contains("dark")) return true
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) return true
    return false
  })

  // Apply as early as possible to reduce flicker
  React.useLayoutEffect(() => {
    if (typeof document === "undefined") return
    const html = document.documentElement
    html.classList.toggle("dark", isDark)
    html.setAttribute("data-theme", isDark ? "dark" : "light")
    try {
      localStorage.setItem("theme", isDark ? "dark" : "light")
    } catch {}
    // Notify listeners (e.g., ReDoc page) that theme changed
    try {
      const evt = new CustomEvent("themechange", { detail: { mode: isDark ? "dark" : "light" } })
      window.dispatchEvent(evt)
    } catch {}
  }, [isDark])

  return (
    <button
      onClick={() => setIsDark((v) => !v)}
      className="inline-flex items-center gap-2 rounded-md px-2 py-1 text-sm"
      aria-pressed={isDark}
    >
      {isDark ? "Dark" : "Light"}
    </button>
  )
}

export default ThemeToggle