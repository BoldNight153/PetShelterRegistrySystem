import { Link } from 'react-router-dom'
import { Shield, Users, KeyRound, BadgeCheck, LayoutDashboard, BookOpen, Settings, ChevronRight, FileText } from 'lucide-react'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import {
  SidebarGroup,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
} from '@/components/ui/sidebar'
import { useAuth } from '@/lib/auth-context'

const ADMIN_ROLES = new Set(['system_admin','admin','shelter_admin','staff_manager'])

export default function NavAdmin() {
  const { user } = useAuth()
  const roles = user?.roles || []
  const canSee = roles.some(r => ADMIN_ROLES.has(r))
  if (!canSee) return null
  const isSystemAdmin = roles.includes('system_admin')
  const isAdmin = isSystemAdmin || roles.includes('admin')
  return (
    <SidebarGroup>
      <SidebarGroupLabel>Admin</SidebarGroupLabel>
      <SidebarMenu>
        <SidebarMenuItem>
          <SidebarMenuButton asChild>
            <Link to="/admin/roles"><BadgeCheck className="h-4 w-4" /><span>Roles</span></Link>
          </SidebarMenuButton>
        </SidebarMenuItem>
        <SidebarMenuItem>
          <SidebarMenuButton asChild>
            <Link to="/admin/permissions"><KeyRound className="h-4 w-4" /><span>Permissions</span></Link>
          </SidebarMenuButton>
        </SidebarMenuItem>
        <SidebarMenuItem>
          <SidebarMenuButton asChild>
            <Link to="/admin/users"><Users className="h-4 w-4" /><span>User Roles</span></Link>
          </SidebarMenuButton>
        </SidebarMenuItem>
        {isAdmin && (
          <SidebarMenuItem>
            <SidebarMenuButton asChild>
              <Link to="/admin/audit-logs"><Shield className="h-4 w-4" /><span>Audit Logs</span></Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        )}

        {isSystemAdmin && (
          <Collapsible asChild defaultOpen={false} className="group/collapsible">
            <SidebarMenuItem>
              <CollapsibleTrigger asChild>
                <SidebarMenuButton tooltip="Docs">
                  <FileText className="h-4 w-4" />
                  <span>Docs</span>
                  <ChevronRight className="ml-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
                </SidebarMenuButton>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <SidebarMenuSub>
                  <SidebarMenuSubItem>
                    <Collapsible defaultOpen={false} className="group/collapsible">
                      <div>
                        <CollapsibleTrigger asChild>
                          <SidebarMenuSubButton>
                            <BookOpen className="h-4 w-4" />
                            <span>APIs</span>
                            <ChevronRight className="ml-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
                          </SidebarMenuSubButton>
                        </CollapsibleTrigger>
                        <CollapsibleContent>
                          <SidebarMenuSub>
                            {/* Pets API */}
                            <SidebarMenuSubItem>
                              <Collapsible defaultOpen={false} className="group/collapsible">
                                <div>
                                  <CollapsibleTrigger asChild>
                                    <SidebarMenuSubButton>
                                      <span>Pets REST API</span>
                                      <ChevronRight className="ml-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
                                    </SidebarMenuSubButton>
                                  </CollapsibleTrigger>
                                  <CollapsibleContent>
                                    <SidebarMenuSub>
                                      <SidebarMenuSubItem>
                                        <SidebarMenuSubButton asChild>
                                          <Link to="/docs/api/pets/spec"><span>ReDoc API Docs</span></Link>
                                        </SidebarMenuSubButton>
                                      </SidebarMenuSubItem>
                                      <SidebarMenuSubItem>
                                        <SidebarMenuSubButton asChild>
                                          <Link to="/docs/api/pets/introduction"><span>Introduction</span></Link>
                                        </SidebarMenuSubButton>
                                      </SidebarMenuSubItem>
                                      <SidebarMenuSubItem>
                                        <SidebarMenuSubButton asChild>
                                          <Link to="/docs/api/pets/get-started"><span>Get Started</span></Link>
                                        </SidebarMenuSubButton>
                                      </SidebarMenuSubItem>
                                      <SidebarMenuSubItem>
                                        <SidebarMenuSubButton asChild>
                                          <Link to="/docs/api/pets/tutorials"><span>Tutorials</span></Link>
                                        </SidebarMenuSubButton>
                                      </SidebarMenuSubItem>
                                      <SidebarMenuSubItem>
                                        <SidebarMenuSubButton asChild>
                                          <Link to="/docs/api/pets/changelog"><span>Changelog</span></Link>
                                        </SidebarMenuSubButton>
                                      </SidebarMenuSubItem>
                                    </SidebarMenuSub>
                                  </CollapsibleContent>
                                </div>
                              </Collapsible>
                            </SidebarMenuSubItem>

                            {/* Auth API */}
                            <SidebarMenuSubItem>
                              <Collapsible defaultOpen={false} className="group/collapsible">
                                <div>
                                  <CollapsibleTrigger asChild>
                                    <SidebarMenuSubButton>
                                      <span>Auth REST API</span>
                                      <ChevronRight className="ml-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
                                    </SidebarMenuSubButton>
                                  </CollapsibleTrigger>
                                  <CollapsibleContent>
                                    <SidebarMenuSub>
                                      <SidebarMenuSubItem>
                                        <SidebarMenuSubButton asChild>
                                          <Link to="/docs/api/auth/spec"><span>ReDoc API Docs</span></Link>
                                        </SidebarMenuSubButton>
                                      </SidebarMenuSubItem>
                                      <SidebarMenuSubItem>
                                        <SidebarMenuSubButton asChild>
                                          <Link to="/docs/api/auth/introduction"><span>Introduction</span></Link>
                                        </SidebarMenuSubButton>
                                      </SidebarMenuSubItem>
                                      <SidebarMenuSubItem>
                                        <SidebarMenuSubButton asChild>
                                          <Link to="/docs/api/auth/get-started"><span>Get Started</span></Link>
                                        </SidebarMenuSubButton>
                                      </SidebarMenuSubItem>
                                      <SidebarMenuSubItem>
                                        <SidebarMenuSubButton asChild>
                                          <Link to="/docs/api/auth/tutorials"><span>Tutorials</span></Link>
                                        </SidebarMenuSubButton>
                                      </SidebarMenuSubItem>
                                      <SidebarMenuSubItem>
                                        <SidebarMenuSubButton asChild>
                                          <Link to="/docs/api/auth/changelog"><span>Changelog</span></Link>
                                        </SidebarMenuSubButton>
                                      </SidebarMenuSubItem>
                                    </SidebarMenuSub>
                                  </CollapsibleContent>
                                </div>
                              </Collapsible>
                            </SidebarMenuSubItem>

                            {/* Admin API */}
                            <SidebarMenuSubItem>
                              <Collapsible defaultOpen={false} className="group/collapsible">
                                <div>
                                  <CollapsibleTrigger asChild>
                                    <SidebarMenuSubButton>
                                      <span>Admin REST API</span>
                                      <ChevronRight className="ml-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
                                    </SidebarMenuSubButton>
                                  </CollapsibleTrigger>
                                  <CollapsibleContent>
                                    <SidebarMenuSub>
                                      <SidebarMenuSubItem>
                                        <SidebarMenuSubButton asChild>
                                          <Link to="/docs/api/admin/spec"><span>ReDoc API Docs</span></Link>
                                        </SidebarMenuSubButton>
                                      </SidebarMenuSubItem>
                                      <SidebarMenuSubItem>
                                        <SidebarMenuSubButton asChild>
                                          <Link to="/docs/api/admin/introduction"><span>Introduction</span></Link>
                                        </SidebarMenuSubButton>
                                      </SidebarMenuSubItem>
                                      <SidebarMenuSubItem>
                                        <SidebarMenuSubButton asChild>
                                          <Link to="/docs/api/admin/get-started"><span>Get Started</span></Link>
                                        </SidebarMenuSubButton>
                                      </SidebarMenuSubItem>
                                      <SidebarMenuSubItem>
                                        <SidebarMenuSubButton asChild>
                                          <Link to="/docs/api/admin/tutorials"><span>Tutorials</span></Link>
                                        </SidebarMenuSubButton>
                                      </SidebarMenuSubItem>
                                      <SidebarMenuSubItem>
                                        <SidebarMenuSubButton asChild>
                                          <Link to="/docs/api/admin/changelog"><span>Changelog</span></Link>
                                        </SidebarMenuSubButton>
                                      </SidebarMenuSubItem>
                                    </SidebarMenuSub>
                                  </CollapsibleContent>
                                </div>
                              </Collapsible>
                            </SidebarMenuSubItem>
                          </SidebarMenuSub>
                        </CollapsibleContent>
                      </div>
                    </Collapsible>
                  </SidebarMenuSubItem>
                  {/* Siblings to APIs under Docs */}
                  <SidebarMenuSubItem>
                    <SidebarMenuSubButton asChild>
                      <Link to="/docs/architecture"><span>Architecture</span></Link>
                    </SidebarMenuSubButton>
                  </SidebarMenuSubItem>
                  <SidebarMenuSubItem>
                    <SidebarMenuSubButton asChild>
                      <Link to="/docs/client-sdks"><span>Client SDKs</span></Link>
                    </SidebarMenuSubButton>
                  </SidebarMenuSubItem>
                </SidebarMenuSub>
              </CollapsibleContent>
            </SidebarMenuItem>
          </Collapsible>
        )}

        

        {isSystemAdmin && (
          <Collapsible asChild defaultOpen={false} className="group/collapsible">
            <SidebarMenuItem>
              <CollapsibleTrigger asChild>
                <SidebarMenuButton tooltip="Server">
                  <LayoutDashboard className="h-4 w-4" />
                  <span>Server</span>
                  <ChevronRight className="ml-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
                </SidebarMenuButton>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <SidebarMenuSub>
                  <SidebarMenuSubItem>
                    <SidebarMenuSubButton asChild>
                      <Link to="/admin/server-info"><span>Dashboards</span></Link>
                    </SidebarMenuSubButton>
                  </SidebarMenuSubItem>
                  <SidebarMenuSubItem>
                    <SidebarMenuSubButton asChild>
                      <Link to="/admin/server-info/charts"><span>Charts</span></Link>
                    </SidebarMenuSubButton>
                  </SidebarMenuSubItem>
                </SidebarMenuSub>
              </CollapsibleContent>
            </SidebarMenuItem>
          </Collapsible>
        )}

        {isSystemAdmin && (
          <SidebarMenuItem>
            <SidebarMenuButton asChild tooltip="Settings">
              <Link to="/admin/settings">
                <Settings className="h-4 w-4" />
                <span>Settings</span>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        )}
      </SidebarMenu>
    </SidebarGroup>
  )
}
