import { useParams } from 'react-router-dom'
import MarkdownView from '@/components/docs/markdown-view'

type ApiKey = 'pets' | 'auth' | 'admin'

export default function DocsIntroduction() {
  const { api } = useParams<{ api: ApiKey }>()
  const which: ApiKey = (api === 'auth' || api === 'admin') ? api : 'pets'
  const pathMap: Record<ApiKey, string> = {
    pets: '/src/docs/content/apis/pets/introduction.md',
    auth: '/src/docs/content/apis/auth/introduction.md',
    admin: '/src/docs/content/apis/admin/introduction.md',
  }
  return <MarkdownView path={pathMap[which]} />
}
