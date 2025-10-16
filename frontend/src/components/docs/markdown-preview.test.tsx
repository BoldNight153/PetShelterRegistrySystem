import { describe, it, expect } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import React from 'react'
import { renderSimple, mockFetchOnce } from '@/lib/test-utils'
import { MarkdownPreview } from './markdown-preview'

// Basic happy path: renders markdown content
describe('MarkdownPreview', () => {
  it('renders markdown on success', async () => {
    const restore = mockFetchOnce({ status: 200, body: '# Hello\n\nThis is a test.' })
    renderSimple(<MarkdownPreview target="backend" kind="readme" />)

    // shows loading first
    expect(await screen.findByText(/Loading/i)).toBeInTheDocument()

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
})
