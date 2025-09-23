import React from 'react'
import { cn } from '../lib/utils'

export default function Card({ children, className = '' }) {
  return (
    <div className={cn('rounded-lg border p-4 shadow-sm bg-card text-card-foreground border-border', className)}>
      {children}
    </div>
  )
}
