import { create } from 'zustand'
import type { Settings } from '@shared/types'

interface SettingsStore extends Settings {
  updateSettings: (updates: Partial<Settings>) => void
}

export const useSettingsStore = create<SettingsStore>((set) => ({
  openrouterKey: '',
  byokKeys: {},
  defaultModel: 'anthropic/claude-sonnet-4.6',
  confidenceThreshold: 85,
  retryLimit: 2,
  modelPreferences: {},
  soundEnabled: true,
  pipEnabled: false,

  updateSettings: (updates) => set((s) => ({ ...s, ...updates }))
}))
