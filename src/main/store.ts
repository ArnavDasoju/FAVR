/**
 * Persistent settings store — wraps electron-store.
 * Loads on startup, saves on change, pushes config to queue/agentManager.
 */

import Store from 'electron-store'
import { taskQueue } from './tasks/queue'
import { agentManager } from './agents/manager'
import { modelRouter } from './optimization/router'

interface PersistedSettings {
  openrouterKey: string
  geminiApiKey: string
  defaultModel: string
  confidenceThreshold: number
  retryLimit: number
  modelPreferences: Record<string, string>
  projects: Array<{
    id: string
    name: string
    directory: string
    devServerUrl: string | null
  }>
}

const store = new Store<PersistedSettings>({
  name: 'bld-settings',
  defaults: {
    openrouterKey: '',
    geminiApiKey: '',
    defaultModel: 'anthropic/claude-sonnet-4.6',
    confidenceThreshold: 85,
    retryLimit: 2,
    modelPreferences: {},
    projects: []
  },
  encryptionKey: 'bld-v1' // Basic encryption for API keys at rest
})

/**
 * Load persisted settings and push to all backend modules.
 */
export function loadSettings(): void {
  const openrouterKey = store.get('openrouterKey')
  const geminiApiKey = store.get('geminiApiKey')
  const confidenceThreshold = store.get('confidenceThreshold')
  const retryLimit = store.get('retryLimit')
  const modelPreferences = store.get('modelPreferences')
  const projects = store.get('projects')

  if (openrouterKey) agentManager.setOpenRouterKey(openrouterKey)
  if (geminiApiKey) taskQueue.setGeminiApiKey(geminiApiKey)
  if (confidenceThreshold) taskQueue.setConfidenceThreshold(confidenceThreshold)
  if (retryLimit) taskQueue.setMaxRetries(retryLimit)
  if (modelPreferences) taskQueue.setModelPreferences(modelPreferences)

  // Restore project directories
  for (const p of projects) {
    taskQueue.setProjectDir(p.id, p.directory)
    if (p.devServerUrl) taskQueue.setDevServerUrl(p.id, p.devServerUrl)
  }

  // Fall back to env vars if no keys in store
  if (!geminiApiKey && process.env.GEMINI_API_KEY) {
    taskQueue.setGeminiApiKey(process.env.GEMINI_API_KEY)
    console.log('[store] Using GEMINI_API_KEY from .env')
  }
  if (!openrouterKey && process.env.OPENROUTER_API_KEY) {
    agentManager.setOpenRouterKey(process.env.OPENROUTER_API_KEY)
    console.log('[store] Using OPENROUTER_API_KEY from .env')
  }

  console.log(`[store] Loaded settings — ${projects.length} projects, gemini: ${geminiApiKey || process.env.GEMINI_API_KEY ? 'set' : 'none'}, openrouter: ${openrouterKey ? 'set' : 'none'}`)
}

/**
 * Save a setting and push to relevant modules.
 */
export function saveSetting(key: string, value: unknown): void {
  store.set(key as keyof PersistedSettings, value as any)

  // Push to backend modules
  switch (key) {
    case 'openrouterKey':
      if (typeof value === 'string' && value) agentManager.setOpenRouterKey(value)
      break
    case 'geminiApiKey':
      if (typeof value === 'string' && value) taskQueue.setGeminiApiKey(value)
      break
    case 'confidenceThreshold':
      if (typeof value === 'number') taskQueue.setConfidenceThreshold(value)
      break
    case 'retryLimit':
      if (typeof value === 'number') taskQueue.setMaxRetries(value)
      break
    case 'modelPreferences':
      if (typeof value === 'object' && value) taskQueue.setModelPreferences(value as Record<string, string>)
      break
  }
}

/**
 * Save multiple settings at once.
 */
export function saveSettings(settings: Partial<PersistedSettings>): void {
  for (const [key, value] of Object.entries(settings)) {
    if (value !== undefined) {
      saveSetting(key, value)
    }
  }
}

/**
 * Get all persisted settings for sending to renderer.
 */
export function getSettings(): PersistedSettings {
  return {
    openrouterKey: store.get('openrouterKey'),
    geminiApiKey: store.get('geminiApiKey'),
    defaultModel: store.get('defaultModel'),
    confidenceThreshold: store.get('confidenceThreshold'),
    retryLimit: store.get('retryLimit'),
    modelPreferences: store.get('modelPreferences'),
    projects: store.get('projects')
  }
}

/**
 * Save a project to persistent store.
 */
export function saveProject(project: { id: string; name: string; directory: string; devServerUrl: string | null }): void {
  const projects = store.get('projects')
  const existing = projects.findIndex((p) => p.id === project.id)
  if (existing >= 0) {
    projects[existing] = project
  } else {
    projects.push(project)
  }
  store.set('projects', projects)
}

/**
 * Remove a project from persistent store.
 */
export function removeProject(projectId: string): void {
  const projects = store.get('projects').filter((p) => p.id !== projectId)
  store.set('projects', projects)
}

export { store }
