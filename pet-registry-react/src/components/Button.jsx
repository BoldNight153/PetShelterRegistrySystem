import React from 'react'
import { cn } from '../lib/utils'

export default function Button({ children, className = '', variant = 'default', ...props }) {
  const base = 'inline-flex items-center gap-2 px-4 py-2 rounded-md font-medium focus:outline-none focus:ring-2 focus:ring-offset-2'
  const variants = {
    default: 'bg-primary text-primary-foreground hover:brightness-90',
    destructive: 'bg-destructive text-destructive-foreground hover:brightness-90',
    ghost: 'bg-transparent text-foreground hover:bg-muted/5'
  }

  return (
    <button className={cn(base, variants[variant], className)} {...props}>
      {children}
    </button>
  )
}
