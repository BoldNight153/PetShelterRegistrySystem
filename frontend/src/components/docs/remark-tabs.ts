/* A tiny remark plugin to transform :::tabs directives into a div with data-tabs for ReactMarkdown */
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import { visit } from 'unist-util-visit'

export function remarkTabs() {
  return (tree) => {
    visit(
      tree,
      (node) => node.type === 'containerDirective' || node.type === 'leafDirective',
      (node) => {
        if (node.name !== 'tabs') return
        node.data = node.data || {}
        node.data.hName = 'div'
        node.data.hProperties = { 'data-tabs': 'true' }
      }
    )
  }
}
