import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { AuthProvider } from '@/lib/auth-context'
import RootLayout from '@/layout/root-layout'
import RegisterPage from '@/pages/register'
import { ServicesProvider } from '@/services/provider'

const loginMock = vi.fn(async (input: { email: string; password: string }) => ({ email: input.email, name: 'User' }))
const refreshMock = vi.fn(async () => ({ ok: true }))
const logoutMock = vi.fn(async () => { /* void */ })
const registerMock = vi.fn(async (input: { email: string; password: string; name?: string }) => ({ email: input.email, name: input.name ?? 'User' }))

describe('SPA /signup opens Register drawer', () => {
  it('keeps URL at /signup, opens register drawer, and hides duplicate route content', async () => {
    render(
      <MemoryRouter initialEntries={["/signup"]}>
        <ServicesProvider services={{ auth: { login: loginMock, refresh: refreshMock, logout: logoutMock, register: registerMock } }}>
          <AuthProvider>
            <Routes>
              <Route element={<RootLayout />}> 
                <Route path="/" element={<div />} />
                {/* Alias route for crawlers/direct links */}
                <Route path="/signup" element={<RegisterPage />} />
              </Route>
            </Routes>
          </AuthProvider>
        </ServicesProvider>
      </MemoryRouter>
    )

    // Drawer should be open with register view. Look for drawer overlay and register submit button.
    await waitFor(() => {
      const overlay = document.querySelector('[data-slot="drawer-overlay"]')
      expect(overlay).toBeTruthy()
    })

    // Ensure we see the register form inside the drawer
    const createAccountBtn = await screen.findByRole('button', { name: /create account/i })
    expect(createAccountBtn).toBeInTheDocument()

    // Underlying route content should be hidden when drawer is open, so only a single Email field exists
    const emailFields = screen.getAllByLabelText(/email/i)
    expect(emailFields.length).toBe(1)

    // Close button rendered by the drawer exists
    expect(screen.getByRole('button', { name: /close/i })).toBeInTheDocument()
  })
})
