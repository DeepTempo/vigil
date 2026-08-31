import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import UserMenu from './UserMenu'

const auth = vi.hoisted(() => ({
  user: {
    username: 'dev-user',
    full_name: 'Test User' as string | null,
    email: 'dev@localhost',
    role_id: 'role-admin',
    mfa_enabled: false,
  },
  logout: vi.fn(),
}))

vi.mock('../contexts/AuthContext', () => ({
  useAuth: () => auth,
}))

function renderMenu() {
  return render(
    <MemoryRouter>
      <UserMenu />
    </MemoryRouter>,
  )
}

describe('UserMenu', () => {
  it('renders initials and labels from full_name', () => {
    auth.user.full_name = 'Test User'
    renderMenu()
    expect(screen.getByText('TU')).toBeInTheDocument()
    expect(screen.getAllByText('Test User').length).toBeGreaterThan(0)
  })

  it('falls back to username when full_name is null', async () => {
    auth.user.full_name = null
    renderMenu()
    expect(screen.getByRole('button', { name: 'Account menu' })).toBeInTheDocument()
    expect(screen.getByText('D')).toBeInTheDocument()
    expect(screen.getAllByText('dev-user').length).toBeGreaterThan(0)

    fireEvent.click(screen.getByRole('button', { name: 'Account menu' }))
    const menu = await screen.findByRole('menu', { name: 'Account' })
    expect(menu).toHaveTextContent('dev-user')
  })
})
