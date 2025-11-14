import { describe, it, expect, beforeEach, afterEach, vi } from "vitest"
import { render, screen, fireEvent, waitFor } from "@testing-library/react"
import ProfileSettingsPage from "./profile"
import type { UserDetail } from "@/services/interfaces/types"

const baseUser: UserDetail = {
  id: "user-1",
  email: "avery@example.com",
  name: "Avery Handler",
  roles: ["staff", "admin"],
  permissions: ["settings:read"],
  lock: null,
  image: "https://cdn.example.com/avatar.png",
  createdAt: "2024-01-05T10:00:00.000Z",
  updatedAt: "2024-02-01T18:30:00.000Z",
  lastLoginAt: "2024-02-10T12:45:00.000Z",
  metadata: {
    title: "Director",
    department: "Shelter Ops",
    pronouns: "she/her",
    timezone: "America/Los_Angeles",
    locale: "en-US",
    phone: "555-555-1234",
    bio: "Oversees day-to-day operations.",
  },
}

function cloneUser(): UserDetail {
  return JSON.parse(JSON.stringify(baseUser)) as UserDetail
}

let currentUser: UserDetail | null = cloneUser()
let initializingFlag = false
const updateProfileMock = vi.fn()

vi.mock("@/lib/auth-context", () => ({
  useAuth: () => ({
    user: currentUser,
    updateProfile: updateProfileMock,
    initializing: initializingFlag,
    authenticated: true,
    login: vi.fn(),
    register: vi.fn(),
    logout: vi.fn(),
    setUser: vi.fn(),
  }),
}))

vi.mock("sonner", () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}))

describe("ProfileSettingsPage", () => {
  beforeEach(() => {
    currentUser = cloneUser()
    initializingFlag = false
    updateProfileMock.mockReset()
  })

  afterEach(() => {
    currentUser = cloneUser()
    initializingFlag = false
  })

  it("prefills the form with existing profile data", () => {
    render(<ProfileSettingsPage />)

    expect(screen.getByLabelText(/Full name/i)).toHaveValue("Avery Handler")
    expect(screen.getByLabelText(/Title/i)).toHaveValue("Director")
    expect(screen.getByLabelText(/Department/i)).toHaveValue("Shelter Ops")
    expect(screen.getByLabelText(/Pronouns/i)).toHaveValue("she/her")
    expect(screen.getByLabelText(/Timezone/i)).toHaveValue("America/Los_Angeles")
    expect(screen.getByLabelText(/Locale/i)).toHaveValue("en-US")
    expect(screen.getByLabelText(/Phone/i)).toHaveValue("555-555-1234")
    expect(screen.getByLabelText(/Avatar image URL/i)).toHaveValue("https://cdn.example.com/avatar.png")
    expect(screen.getByLabelText(/Bio/i)).toHaveValue("Oversees day-to-day operations.")
  })

  it("submits updates with normalized payload", async () => {
    updateProfileMock.mockResolvedValue({
      ...cloneUser(),
      name: "Avery H.",
      metadata: {
        ...baseUser.metadata,
        bio: "Ready to help every pet find a home.",
      },
    })

    render(<ProfileSettingsPage />)

    fireEvent.change(screen.getByLabelText(/Full name/i), { target: { value: "Avery H." } })
    fireEvent.change(screen.getByLabelText(/Bio/i), { target: { value: "Ready to help every pet find a home." } })

    const saveButton = screen.getByRole("button", { name: /save changes/i })
    fireEvent.click(saveButton)

    await waitFor(() => expect(updateProfileMock).toHaveBeenCalledTimes(1))

    expect(updateProfileMock.mock.calls[0][0]).toMatchObject({
      name: "Avery H.",
      bio: "Ready to help every pet find a home.",
    })

    expect(screen.getByLabelText(/Full name/i)).toHaveValue("Avery H.")
    expect(saveButton).toBeDisabled()
  })

  it("renders a loading state while auth context initializes", () => {
    initializingFlag = true
    currentUser = null

    render(<ProfileSettingsPage />)

    expect(screen.getByText(/Loading profile/i)).toBeInTheDocument()
  })
})
