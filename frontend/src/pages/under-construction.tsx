import { useLocation, useNavigate } from "react-router-dom"

import { StatusPage } from "@/components/errors/status-page"
import { getStatusDescriptor } from "@/components/errors/status-definitions"
import { resolveStatusActions } from "@/components/errors/resolve-status-actions"

export type UnderConstructionPageProps = {
  feature?: string
  message?: string
}

export default function UnderConstructionPage({ feature, message }: UnderConstructionPageProps) {
  const navigate = useNavigate()
  const location = useLocation()
  const descriptor = getStatusDescriptor("501")
  const actions = resolveStatusActions(descriptor, navigate, location)
  const effectiveMessage =
    message ??
    (feature
      ? `${feature} is still in development. We'll ship this workflow soon.`
      : descriptor.description)

  return <StatusPage descriptor={descriptor} actions={actions} message={effectiveMessage} />
}
