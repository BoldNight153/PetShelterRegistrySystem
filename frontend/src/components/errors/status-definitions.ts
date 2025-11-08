import {
  AlertTriangle,
  Ban,
  Clock3,
  FileWarning,
  Hammer,
  LockKeyhole,
  Network,
  ShieldAlert,
  ShieldBan,
  SignalHigh,
  WifiOff,
} from "lucide-react"
import type { LucideIcon } from "lucide-react"

export type StatusActionKind =
  | "back"
  | "home"
  | "dashboard"
  | "reload"
  | "login"
  | "support"
  | "contact"
  | "docs"

export type StatusDescriptor = {
  code: number
  title: string
  description: string
  icon: LucideIcon
  severity?: "info" | "warning" | "error"
  actions?: Array<{
    kind: StatusActionKind
    label?: string
    href?: string
  }>
}

export const STATUS_DEFINITIONS: Record<string, StatusDescriptor> = {
  "401": {
    code: 401,
    title: "Authentication required",
    description:
      "You need to be signed in to access this area. Log in with an account that has the appropriate permissions.",
    icon: ShieldBan,
    severity: "warning",
    actions: [
      { kind: "login", label: "Sign in" },
      { kind: "back", label: "Go back" },
    ],
  },
  "403": {
    code: 403,
    title: "Access denied",
    description:
      "Your account does not have access to this resource. If you believe this is an error, contact an administrator.",
    icon: Ban,
    severity: "warning",
    actions: [
      { kind: "back", label: "Go back" },
      { kind: "dashboard", label: "Return to dashboard" },
      { kind: "contact", label: "Request access" },
    ],
  },
  "404": {
    code: 404,
    title: "Page not found",
    description:
      "The page you’re looking for doesn’t exist or may have been moved. Check the URL or choose another section.",
    icon: FileWarning,
    severity: "info",
    actions: [
      { kind: "back", label: "Go back" },
      { kind: "dashboard", label: "Back to dashboard" },
    ],
  },
  "409": {
    code: 409,
    title: "Update conflict",
    description:
      "Another change was applied before yours could be saved. Refresh to load the latest data and try again.",
    icon: AlertTriangle,
    severity: "warning",
    actions: [
      { kind: "reload", label: "Refresh and retry" },
      { kind: "back", label: "Go back" },
    ],
  },
  "422": {
    code: 422,
    title: "Validation required",
    description:
      "We couldn’t process that request with the provided data. Review the form for detailed validation messages.",
    icon: ShieldAlert,
    severity: "warning",
    actions: [
      { kind: "back", label: "Review form" },
    ],
  },
  "423": {
    code: 423,
    title: "Account locked",
    description:
      "We temporarily locked this account for security reasons. Try again later or contact support to regain access.",
    icon: LockKeyhole,
    severity: "error",
    actions: [
      { kind: "support", label: "Contact support" },
      { kind: "back", label: "Go back" },
    ],
  },
  "429": {
    code: 429,
    title: "Too many requests",
    description:
      "You hit the request limit for this action. Wait a moment before trying again to avoid being locked out.",
    icon: SignalHigh,
    severity: "warning",
    actions: [
      { kind: "reload", label: "Try again" },
      { kind: "docs", label: "View rate limits" },
    ],
  },
  "500": {
    code: 500,
    title: "Something went wrong",
    description:
      "We encountered an unexpected error while processing your request. Our team has been notified.",
    icon: Network,
    severity: "error",
    actions: [
      { kind: "reload", label: "Reload page" },
      { kind: "support", label: "Report issue" },
    ],
  },
  "502": {
    code: 502,
    title: "Upstream response error",
    description:
      "A connected service failed to respond correctly. This is usually temporary—try the request again shortly.",
    icon: WifiOff,
    severity: "error",
    actions: [
      { kind: "reload", label: "Retry" },
      { kind: "dashboard", label: "Return to dashboard" },
    ],
  },
  "503": {
    code: 503,
    title: "Scheduled maintenance",
    description:
      "We’re performing routine maintenance. Services will be back online soon. Thanks for your patience!",
    icon: Clock3,
    severity: "info",
    actions: [
      { kind: "reload", label: "Check again" },
      { kind: "docs", label: "View status page" },
    ],
  },
  "504": {
    code: 504,
    title: "Timed out",
    description:
      "The request took longer than expected. This might be due to heavy traffic. Try again in a few moments.",
    icon: WifiOff,
    severity: "warning",
    actions: [
      { kind: "reload", label: "Retry" },
      { kind: "back", label: "Go back" },
    ],
  },
  "501": {
    code: 501,
    title: "Feature in development",
    description:
      "This area of the console is still being built. Check back soon for the finished experience.",
    icon: Hammer,
    severity: "info",
    actions: [
      { kind: "back", label: "Go back" },
      { kind: "dashboard", label: "Back to dashboard" },
    ],
  },
  default: {
    code: 520,
    title: "Unexpected error",
    description:
      "An unknown error occurred. Try again, and if the issue persists, reach out to support with the details",
    icon: AlertTriangle,
    severity: "error",
    actions: [
      { kind: "reload", label: "Reload" },
      { kind: "support", label: "Contact support" },
    ],
  },
}

export function getStatusDescriptor(code: string | number): StatusDescriptor {
  const key = String(code)
  return STATUS_DEFINITIONS[key] ?? STATUS_DEFINITIONS.default
}
