import React from 'react'
import { Link } from 'react-router-dom'
import { cn } from '../lib/utils'

export default function Header() {
  return (
    <header className={cn('border-b bg-background') }>
      <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-3">
          <div className="w-10 h-10 bg-primary rounded-md flex items-center justify-center text-primary-foreground font-bold">PS</div>
          <div>
            <h1 className="text-xl font-semibold">Pet Shelter Registry</h1>
            <p className="text-sm text-muted">Manage registered pets with confidence</p>
          </div>
        </Link>

        <nav>
          <Link to="/add" className="inline-block"><button className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-primary text-primary-foreground">Add Pet</button></Link>
        </nav>
      </div>
    </header>
  )
}
