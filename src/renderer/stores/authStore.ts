import { create } from 'zustand'

interface AuthState {
  isAuthenticated: boolean
  user: { id: string; email: string } | null
  profile: { tier: string; credits: number; stripe_customer_id: string | null } | null
  loading: boolean
  error: string | null

  setAuth: (data: { isAuthenticated: boolean; user: any; profile: any }) => void
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
  login: (email: string, password: string) => Promise<boolean>
  signup: (email: string, password: string) => Promise<boolean>
  logout: () => Promise<void>
  refreshStatus: () => Promise<void>
}

export const useAuthStore = create<AuthState>((set) => ({
  isAuthenticated: false,
  user: null,
  profile: null,
  loading: false,
  error: null,

  setAuth: (data) =>
    set({ isAuthenticated: data.isAuthenticated, user: data.user, profile: data.profile }),

  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error }),

  login: async (email, password) => {
    set({ loading: true, error: null })
    try {
      const result = (await window.api.invoke('auth:login', { email, password })) as {
        success: boolean
        error?: string
      }
      if (result.success) {
        await useAuthStore.getState().refreshStatus()
        set({ loading: false })
        return true
      }
      set({ loading: false, error: result.error ?? 'Login failed' })
      return false
    } catch (err) {
      set({ loading: false, error: 'Login failed' })
      return false
    }
  },

  signup: async (email, password) => {
    set({ loading: true, error: null })
    try {
      const result = (await window.api.invoke('auth:signup', { email, password })) as {
        success: boolean
        error?: string
      }
      if (result.success) {
        await useAuthStore.getState().refreshStatus()
        set({ loading: false })
        return true
      }
      set({ loading: false, error: result.error ?? 'Signup failed' })
      return false
    } catch (err) {
      set({ loading: false, error: 'Signup failed' })
      return false
    }
  },

  logout: async () => {
    await window.api.invoke('auth:logout')
    set({ isAuthenticated: false, user: null, profile: null })
  },

  refreshStatus: async () => {
    try {
      const status = (await window.api.invoke('auth:status')) as {
        isAuthenticated: boolean
        user: any
        profile: any
      }
      set({
        isAuthenticated: status.isAuthenticated,
        user: status.user,
        profile: status.profile
      })
    } catch {
      // Not connected to cloud
    }
  }
}))
