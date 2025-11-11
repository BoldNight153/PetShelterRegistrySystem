import { Link } from "react-router-dom"

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import type { StatusDescriptor } from "./status-definitions"

export type ResolvedStatusAction =
  | {
      key: string
      label: string
      variant?: "default" | "secondary" | "ghost"
      onClick: () => void
    }
  | {
      key: string
      label: string
      variant?: "default" | "secondary" | "ghost"
      href: string
      external?: boolean
    }

export type StatusPageProps = {
  descriptor: StatusDescriptor
  actions?: ResolvedStatusAction[]
  className?: string
  message?: string
}

export function StatusPage({ descriptor, actions = [], className, message }: StatusPageProps) {
  const Icon = descriptor.icon

  return (
    <section
      className={cn(
        "flex h-full min-h-[420px] w-full flex-col items-center justify-center gap-6 text-center",
        className,
      )}
    >
      <span
        className={cn(
          "flex h-16 w-16 items-center justify-center rounded-full border",
          descriptor.severity === "info" && "border-blue-200 bg-blue-50 text-blue-600",
          descriptor.severity === "warning" && "border-amber-200 bg-amber-50 text-amber-600",
          descriptor.severity === "error" && "border-rose-200 bg-rose-50 text-rose-600",
        )}
        aria-hidden
      >
        <Icon className="h-7 w-7" />
      </span>

      <div className="flex max-w-xl flex-col gap-1">
        <h1 className="text-3xl font-semibold tracking-tight">{descriptor.code}</h1>
        <h2 className="text-xl font-medium text-foreground">{descriptor.title}</h2>
        <p className="text-muted-foreground">
          {message ?? descriptor.description}
        </p>
      </div>

      {actions.length > 0 ? (
        <div className="flex flex-wrap items-center justify-center gap-3">
          {actions.map((action) => {
            if ("href" in action) {
              if (!action.external) {
                return (
                  <Button
                    asChild
                    key={action.key}
                    variant={action.variant ?? "secondary"}
                  >
                    <Link to={action.href}>
                      {action.label}
                    </Link>
                  </Button>
                )
              }

              return (
                <Button
                  asChild
                  key={action.key}
                  variant={action.variant ?? "secondary"}
                >
                  <a
                    href={action.href}
                    target={action.external ? "_blank" : undefined}
                    rel={action.external ? "noreferrer" : undefined}
                  >
                    {action.label}
                  </a>
                </Button>
              )
            }

            return (
              <Button
                key={action.key}
                onClick={action.onClick}
                variant={action.variant ?? "default"}
              >
                {action.label}
              </Button>
            )
          })}
        </div>
      ) : null}
    </section>
  )
}
