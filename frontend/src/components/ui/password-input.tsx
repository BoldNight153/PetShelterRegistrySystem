import * as React from "react"
import { Eye, EyeOff } from "lucide-react"
import { cn } from "@/lib/utils"

type Props = React.InputHTMLAttributes<HTMLInputElement> & {
  containerClassName?: string
}

export function PasswordInput({ className, containerClassName, ...props }: Props) {
  const [show, setShow] = React.useState(false)
  return (
    <div className={cn("relative", containerClassName)}>
      <input
        {...props}
        type={show ? "text" : "password"}
        className={cn("w-full border rounded px-3 py-2 pr-9", className)}
      />
      <button
        type="button"
        onClick={() => setShow((v) => !v)}
        className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
        aria-label={show ? "Hide password" : "Show password"}
        tabIndex={-1}
      >
        {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
      </button>
    </div>
  )
}

export default PasswordInput
