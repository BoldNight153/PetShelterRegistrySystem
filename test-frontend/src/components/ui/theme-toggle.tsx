import React from "react";

export function ThemeToggle() {
  const [isDark, setIsDark] = React.useState(
    typeof document !== "undefined" && document.documentElement.classList.contains("dark")
  )

  React.useEffect(() => {
    if (typeof document === "undefined") return
    document.documentElement.classList.toggle("dark", isDark)
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