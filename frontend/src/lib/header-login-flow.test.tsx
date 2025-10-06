import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { AuthProvider } from '@/lib/auth-context'
import RootLayout from '@/layout/root-layout'
import LoginPage from '@/pages/login'

// Mock the API layer used by auth-context
vi.mock('@/lib/api', () => ({
  login: vi.fn(async () => ({ email: 'user@example.com', name: 'User' })),
  refresh: vi.fn(async () => ({ ok: true })),
  logout: vi.fn(async () => ({})),
  register: vi.fn(async () => ({ email: 'user@example.com', name: 'User' })),
}))

describe('Header switches after login', () => {
  it('shows NavUser after successful login submission', async () => {
    render(
      <MemoryRouter initialEntries={["/login"]}>
        <AuthProvider>
          <Routes>
            <Route element={<RootLayout />}> 
              <Route path="/" element={<div />} />
              <Route path="/login" element={<LoginPage />} />
            </Route>
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    )

    const email = await screen.findByLabelText(/email/i)
    const password = await screen.findByLabelText(/password/i, { selector: 'input' })

    fireEvent.change(email, { target: { value: 'user@example.com' } })
    fireEvent.change(password, { target: { value: 'Admin123!@#' } })

    const submit = screen.getByRole('button', { name: /sign in/i })
    fireEvent.click(submit)

    // Wait for header to show NavUser (avatar button is rendered)
    await waitFor(() => {
      // Dropdown trigger has an Avatar inside; use the name text as heuristic
      expect(screen.getAllByText(/user@example.com|user/i).length).toBeGreaterThan(0)
    })
  })
})
