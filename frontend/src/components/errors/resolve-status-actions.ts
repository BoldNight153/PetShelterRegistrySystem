import type { Location, NavigateFunction } from "react-router-dom"

import type { ResolvedStatusAction } from "@/components/errors/status-page"
import type {
  StatusActionKind,
  StatusDescriptor,
} from "@/components/errors/status-definitions"

const SUPPORT_MAILTO = "mailto:support@petshelterregistry.example?subject=Support%20request"

function resolveActionLabel(kind: StatusActionKind) {
  switch (kind) {
    case "back":
      return "Go back"
    case "dashboard":
      return "Dashboard"
    case "home":
      return "Home"
    case "login":
      return "Sign in"
    case "reload":
      return "Retry"
    case "docs":
      return "Read docs"
    case "support":
    case "contact":
      return "Contact support"
    default:
      return "Continue"
  }
}

export function resolveStatusActions(
  descriptor: StatusDescriptor,
  navigate: NavigateFunction,
  location: Location,
): ResolvedStatusAction[] {
  if (!descriptor.actions?.length) return []

  const returnTo = `${location.pathname}${location.search}${location.hash}`

  return descriptor.actions
    .map<ResolvedStatusAction | null>((action, index) => {
      const label = action.label ?? resolveActionLabel(action.kind)
      const key = `${descriptor.code}-${action.kind}-${index}`

      switch (action.kind) {
        case "back":
          return {
            key,
            label,
            variant: "secondary",
            onClick: () => navigate(-1),
          }
        case "home":
          return {
            key,
            label,
            variant: "secondary",
            onClick: () => navigate("/"),
          }
        case "dashboard":
          return {
            key,
            label,
            variant: "secondary",
            onClick: () => navigate("/dashboard"),
          }
        case "login":
          return {
            key,
            label,
            onClick: () => navigate(`/login?returnTo=${encodeURIComponent(returnTo)}`),
          }
        case "reload":
          return {
            key,
            label,
            onClick: () => window.location.reload(),
          }
        case "docs":
          return {
            key,
            label,
            variant: "ghost",
            href: action.href ?? "/docs",
          }
        case "support":
        case "contact":
          return {
            key,
            label,
            variant: "ghost",
            href: action.href ?? SUPPORT_MAILTO,
            external: true,
          }
        default:
          return null
      }
    })
    .filter((action): action is ResolvedStatusAction => Boolean(action))
}
