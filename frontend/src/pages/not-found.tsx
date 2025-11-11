import { useLocation, useNavigate } from "react-router-dom"

import { StatusPage } from "@/components/errors/status-page"
import { getStatusDescriptor } from "@/components/errors/status-definitions"
import { resolveStatusActions } from "@/components/errors/resolve-status-actions"

export default function NotFoundPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const descriptor = getStatusDescriptor("404")
  const actions = resolveStatusActions(descriptor, navigate, location)

  return <StatusPage descriptor={descriptor} actions={actions} />
}
