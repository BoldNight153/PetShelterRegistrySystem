import { ChevronRight, type LucideIcon } from "lucide-react"
import { Link } from "react-router-dom"

import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import {
  SidebarGroup,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
} from "@/components/ui/sidebar"

export type NavLinkItem = {
  title: string
  url: string
  icon?: LucideIcon
  target?: string | null
  external?: boolean
}

export type NavMainItem = NavLinkItem & {
  isActive?: boolean
  items?: NavLinkItem[]
}

export type NavMainProps = {
  items: NavMainItem[]
  label?: string
}

function NavItemLink({ item, compact = false }: { item: NavLinkItem; compact?: boolean }) {
  const href = item.url || "#"
  const iconClass = compact ? "size-3.5" : "size-4"
  const baseClass = compact
    ? "inline-flex items-center gap-1.5 text-xs"
    : "inline-flex items-center gap-2"
  if (item.external) {
    return (
      <a
        href={href}
        target={item.target ?? "_blank"}
        rel="noreferrer noopener"
        className={baseClass}
      >
        {item.icon && <item.icon className={iconClass} />}
        <span>{item.title}</span>
      </a>
    )
  }
  return (
    <Link to={href} className={baseClass}>
      {item.icon && <item.icon className={iconClass} />}
      <span>{item.title}</span>
    </Link>
  )
}

export default function NavMain({ items, label = "Platform" }: NavMainProps) {
  return (
    <SidebarGroup>
      <SidebarGroupLabel>{label}</SidebarGroupLabel>
      <SidebarMenu>
        {items.map((item) => (
          item.items && item.items.length > 0 ? (
            <Collapsible
              key={item.title + (item.url || "")}
              asChild
              defaultOpen={item.isActive}
              className="group/collapsible"
            >
              <SidebarMenuItem>
                <CollapsibleTrigger asChild>
                  <SidebarMenuButton tooltip={item.title}>
                    {item.icon && <item.icon />}
                    <span>{item.title}</span>
                    <ChevronRight className="ml-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
                  </SidebarMenuButton>
                </CollapsibleTrigger>
                <CollapsibleContent>
                    <SidebarMenuSub className="text-sm">
                      {item.items?.map((subItem) => (
                        <SidebarMenuSubItem key={subItem.title + (subItem.url || "") }>
                          <SidebarMenuSubButton asChild className="h-9 text-sm">
                            <NavItemLink item={subItem} compact />
                          </SidebarMenuSubButton>
                        </SidebarMenuSubItem>
                      ))}
                    </SidebarMenuSub>
                </CollapsibleContent>
              </SidebarMenuItem>
            </Collapsible>
          ) : (
            <SidebarMenuItem key={item.title + (item.url || "") }>
              <SidebarMenuButton asChild tooltip={item.title}>
                <NavItemLink item={item} />
              </SidebarMenuButton>
            </SidebarMenuItem>
          )
        ))}
      </SidebarMenu>
    </SidebarGroup>
  )
}
