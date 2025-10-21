import * as React from 'react'

export type TabItem = {
  id: string
  title: string
  content: React.ReactNode
}

export function CodeTabs({ items, initialId }: { items: TabItem[]; initialId?: string }) {
  const [active, setActive] = React.useState(() => initialId ?? items[0]?.id)
  const activeItem = items.find((i) => i.id === active) ?? items[0]
  return (
    <div className="rounded-md border">
      <div className="flex gap-1 border-b bg-muted/60 px-2 py-1 text-xs">
        {items.map((it) => (
          <button
            key={it.id}
            type="button"
            onClick={() => setActive(it.id)}
            className={`rounded px-2 py-1 ${it.id === active ? 'bg-background text-foreground' : 'text-muted-foreground hover:text-foreground'}`}
          >
            {it.title}
          </button>
        ))}
      </div>
      <div className="p-2">
        {activeItem?.content}
      </div>
    </div>
  )
}
