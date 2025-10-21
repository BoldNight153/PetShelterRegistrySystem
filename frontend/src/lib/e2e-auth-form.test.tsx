import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'
import { AuthProvider } from './auth-context'
import LoginPage from '@/pages/login'

function App({ children }: { children: React.ReactNode }) {
  return <BrowserRouter><AuthProvider>{children}</AuthProvider></BrowserRouter>
}

describe('Auth forms (e2e-ish)', () => {
  it('shows success ring on valid login inputs (client-side only)', async () => {
    render(<App><LoginPage /></App>)
  const email = screen.getByLabelText(/email/i)
  const password = screen.getByLabelText(/password/i, { selector: 'input' })

    fireEvent.blur(email)
    fireEvent.change(email, { target: { value: 'user@example.com' } })
    fireEvent.blur(password)
    fireEvent.change(password, { target: { value: 'Secret123!' } })

    await waitFor(() => {
      expect(email.className).toContain('ring-success')
      expect(password.className).toContain('ring-success')
    })
  })
})
