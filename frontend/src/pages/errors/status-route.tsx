import { useMemo } from "react"
import { useLocation, useNavigate, useParams } from "react-router-dom"
import { StatusPage } from "@/components/errors/status-page"
import { getStatusDescriptor } from "@/components/errors/status-definitions"
import { resolveStatusActions } from "@/components/errors/resolve-status-actions"

export default function StatusPageRoute() {
  const { code = "default" } = useParams()
  const navigate = useNavigate()
  const location = useLocation()

  const descriptor = useMemo(() => getStatusDescriptor(code), [code])

  const actions = useMemo(
    () => resolveStatusActions(descriptor, navigate, location),
    [descriptor, navigate, location],
  )

  return <StatusPage descriptor={descriptor} actions={actions} />
}
