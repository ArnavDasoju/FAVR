import { create } from 'zustand'

interface Transaction {
  id: string
  amount: number
  type: 'purchase' | 'task' | 'refund' | 'monthly_free'
  description: string | null
  balance_after: number
  created_at: string
}

interface CreditsState {
  balance: number
  transactions: Transaction[]
  loading: boolean

  setBalance: (balance: number) => void
  setTransactions: (transactions: Transaction[]) => void
  fetchBalance: () => Promise<void>
  fetchHistory: () => Promise<void>
  purchase: (amount: number) => Promise<{ checkout_url?: string; error?: string }>
}

export const useCreditsStore = create<CreditsState>((set) => ({
  balance: 0,
  transactions: [],
  loading: false,

  setBalance: (balance) => set({ balance }),
  setTransactions: (transactions) => set({ transactions }),

  fetchBalance: async () => {
    try {
      const result = (await window.api.invoke('credits:balance')) as any
      set({ balance: typeof result?.balance === 'number' ? result.balance : 0 })
    } catch {
      // Not authenticated or no cloud connection
    }
  },

  fetchHistory: async () => {
    set({ loading: true })
    try {
      const result = (await window.api.invoke('credits:history')) as any
      set({ transactions: Array.isArray(result?.transactions) ? result.transactions : [], loading: false })
    } catch {
      set({ loading: false })
    }
  },

  purchase: async (amount: number) => {
    const result = (await window.api.invoke('credits:purchase', amount)) as {
      checkout_url?: string
      error?: string
    }
    return result
  }
}))
