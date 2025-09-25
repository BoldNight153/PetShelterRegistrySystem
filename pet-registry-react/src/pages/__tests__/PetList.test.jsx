import { describe, it, expect, beforeEach } from 'vitest'
import React from 'react'
import { render, screen } from '@testing-library/react'
import PetList from '../PetList'
import { ToastProvider } from '@/components/ToastProvider'
import { MemoryRouter } from 'react-router-dom'
import axios from 'axios'

vi.mock('axios')

describe('PetList', () => {
  beforeEach(() => {
    axios.get.mockResolvedValue({ status: 200, data: [{ id: 1, name: 'Buddy', type: 'Dog', breed: 'Beagle', dob: null, age: 3 }] })
  })

  it('renders pet list and shows fallback age', async () => {
    render(
      <MemoryRouter>
        <ToastProvider>
          <PetList />
        </ToastProvider>
      </MemoryRouter>
    )
    const pet = await screen.findByText(/Buddy/)
    expect(pet).toBeInTheDocument()
    expect(screen.getByText(/Age: 3 years/)).toBeInTheDocument()
  })
})
