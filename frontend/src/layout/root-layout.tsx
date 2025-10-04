import { Outlet } from "react-router-dom"
import NavUser from "@/components/nav-user"
import TeamSwitcher from "@/components/team-switcher"
import { AudioWaveform, Command, GalleryVerticalEnd } from "lucide-react"
import AppSidebar from "@/components/app-sidebar"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Separator } from "@/components/ui/separator"
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar"

export default function RootLayout() {
  // Reuse the same sample user and teams as the sidebar for now
  const user = { name: "shadcn", email: "m@example.com", avatar: "/avatars/shadcn.jpg" }
  const teams = [
    { name: "Acme Inc", logo: GalleryVerticalEnd, plan: "Enterprise" },
    { name: "Acme Corp.", logo: AudioWaveform, plan: "Startup" },
    { name: "Evil Corp.", logo: Command, plan: "Free" },
  ]
  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <HeaderBar user={user} teams={teams} />
        <main className="flex flex-1 flex-col gap-4 p-4 pt-0 w-full">
          <Outlet />
        </main>
      </SidebarInset>
    </SidebarProvider>
  )
}

function HeaderBar({ user, teams }: { user: { name: string; email: string; avatar: string }; teams: Array<{ name: string; logo: any; plan: string }> }) {
  return (
    <header className="sticky top-0 z-50 flex h-16 shrink-0 items-center justify-between gap-2 border-b border-border bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60 transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-12">
      <div className="flex items-center gap-2 px-4">
        <SidebarTrigger className="-ml-1" />
        <Separator orientation="vertical" className="mr-2 data-[orientation=vertical]:h-4" />
        {/* Mobile-only: show Team Switcher on small screens, hide on md and up */}
        <div className="md:hidden">
          <TeamSwitcher teams={teams} />
        </div>
        <Breadcrumb>
          <BreadcrumbList>
            <BreadcrumbItem className="hidden md:block">
              <BreadcrumbLink href="#">Building Your Application</BreadcrumbLink>
            </BreadcrumbItem>
            <BreadcrumbSeparator className="hidden md:block" />
            <BreadcrumbItem>
              <BreadcrumbPage>Data Fetching</BreadcrumbPage>
            </BreadcrumbItem>
          </BreadcrumbList>
        </Breadcrumb>
      </div>
      <div className="px-3">
        <NavUser user={user} />
      </div>
    </header>
  )
}
