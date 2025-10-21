import { describe, it, expect, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderSimple, mockFetchOnce } from '@/lib/test-utils'
import { MarkdownPreview } from './markdown-preview'

// Basic happy path: renders markdown content
describe('MarkdownPreview', () => {
  it('renders markdown on success', async () => {
    const restore = mockFetchOnce({ status: 200, body: '# Hello\n\nThis is a test.' })
    renderSimple(<MarkdownPreview target="backend" kind="readme" />)

    // shows loading first
    expect(screen.getByText(/Loading/i)).toBeInTheDocument()

    // then content appears
    await waitFor(() => {
      expect(screen.getByText('Hello')).toBeInTheDocument()
      expect(screen.getByText('This is a test.')).toBeInTheDocument()
    })
    restore()
  })

  it('shows 403 error message', async () => {
    const restore = mockFetchOnce({ status: 403, ok: false, body: 'Forbidden' })
    renderSimple(<MarkdownPreview target="backend" kind="readme" />)

    await waitFor(() => {
      expect(screen.getByText(/Requires system_admin role/i)).toBeInTheDocument()
    })

    // ensure retry button is present
    expect(screen.getByRole('button', { name: /Retry/i })).toBeInTheDocument()
    restore()
  })

  it('shows 404 error message', async () => {
    const restore = mockFetchOnce({ status: 404, ok: false, body: 'Not found' })
    renderSimple(<MarkdownPreview target="frontend" kind="changelog" />)

    await waitFor(() => {
      expect(screen.getByText(/Document not found/i)).toBeInTheDocument()
    })
    restore()
  })

  it('retries after error and renders markdown on success', async () => {
    // First call: 403 error, second call: success
    let callCount = 0
    const originalFetch = global.fetch
    ;(global as any).fetch = vi.fn(async () => {
      callCount++
      if (callCount === 1) {
        return {
          ok: false,
          status: 403,
          text: async () => 'Forbidden',
        }
      }
      return {
        ok: true,
        status: 200,
        text: async () => '# Retry Success',
      }
    })
    renderSimple(<MarkdownPreview target="backend" kind="readme" />)

    await waitFor(() => {
      expect(screen.getByText(/Requires system_admin role/i)).toBeInTheDocument()
    })
    const retryBtn = screen.getByRole('button', { name: /Retry/i })
    retryBtn.click()
    // Wait for markdown to appear after loading
    // Wait for markdown to appear after loading
    await waitFor(() => {
      expect(document.body.textContent).toContain('Retry Success')
    })
    ;(global as any).fetch = originalFetch
  })

  it('hides Retry button after successful retry', async () => {
    let callCount = 0
    const originalFetch = global.fetch
    ;(global as any).fetch = vi.fn(async () => {
      callCount++
      if (callCount === 1) {
        return { ok: false, status: 403, text: async () => 'Forbidden' }
      }
      return { ok: true, status: 200, text: async () => '# Hidden Retry' }
    })
    renderSimple(<MarkdownPreview target="backend" kind="readme" />)

    await waitFor(() => {
      expect(screen.getByText(/Requires system_admin role/i)).toBeInTheDocument()
    })
    const retryBtn = screen.getByRole('button', { name: /Retry/i })
    retryBtn.click()

    // After successful retry, Retry button should no longer be in the document
    await waitFor(() => {
      expect(document.body.textContent).toContain('Hidden Retry')
      expect(screen.queryByRole('button', { name: /Retry/i })).toBeNull()
    })
    ;(global as any).fetch = originalFetch
  })
})
