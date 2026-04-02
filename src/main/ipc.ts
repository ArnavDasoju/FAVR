import { ipcMain, dialog, BrowserWindow, shell } from 'electron'
import { taskQueue } from './tasks/queue'
import { agentManager } from './agents/manager'
import { getSettings, saveSettings, saveProject, removeProject as removePersistedProject } from './store'
import { cloudClient } from './cloud/supabase'

export function setupIpc(): void {
  // ── Dialogs ──────────────────────────────────────────────────
  ipcMain.handle('dialog:openDirectory', async () => {
    const win = BrowserWindow.getFocusedWindow()
    if (!win) return null
    const result = await dialog.showOpenDialog(win, {
      properties: ['openDirectory']
    })
    if (result.canceled || result.filePaths.length === 0) return null
    return result.filePaths[0]
  })

  // ── Tasks ────────────────────────────────────────────────────
  ipcMain.handle('task:submit', async (_event, data: { prompt: string; projectId: string; model?: string }) => {
    console.log('[ipc] task:submit', data.prompt, 'project:', data.projectId)
    try {
      const task = await taskQueue.submit(data.prompt, data.projectId, data.model ?? null)
      return task
    } catch (err) {
      console.error('[ipc] task:submit error:', err)
      throw err
    }
  })

  ipcMain.handle('task:approve', async (_event, taskId: string) => {
    console.log('[ipc] task:approve', taskId)
    taskQueue.approve(taskId)
    return { taskId, status: 'approved' }
  })

  ipcMain.handle('task:reject', async (_event, taskId: string) => {
    console.log('[ipc] task:reject', taskId)
    taskQueue.reject(taskId)
    return { taskId, status: 'rejected' }
  })

  ipcMain.handle('task:cancel', async (_event, taskId: string) => {
    console.log('[ipc] task:cancel', taskId)
    taskQueue.cancel(taskId)
    return { taskId }
  })

  ipcMain.handle('task:list', async () => {
    return taskQueue.getAllTasks()
  })

  // ── Agents ───────────────────────────────────────────────────
  ipcMain.handle('agent:list', async () => {
    return agentManager.getAllAgents()
  })

  ipcMain.handle('agent:kill', async (_event, agentId: string) => {
    agentManager.kill(agentId)
    return { agentId }
  })

  // ── Projects ─────────────────────────────────────────────────
  ipcMain.handle('project:setDir', async (_event, data: { projectId: string; directory: string }) => {
    taskQueue.setProjectDir(data.projectId, data.directory)
    return true
  })

  ipcMain.handle('project:setDevServer', async (_event, data: { projectId: string; url: string }) => {
    taskQueue.setDevServerUrl(data.projectId, data.url)
    return true
  })

  ipcMain.handle('project:add', async (_event, project: { id: string; name: string; directory: string; devServerUrl: string | null }) => {
    taskQueue.setProjectDir(project.id, project.directory)
    if (project.devServerUrl) taskQueue.setDevServerUrl(project.id, project.devServerUrl)
    saveProject(project)
    return true
  })

  ipcMain.handle('project:remove', async (_event, projectId: string) => {
    removePersistedProject(projectId)
    return true
  })

  // ── Settings ─────────────────────────────────────────────────
  ipcMain.handle('settings:get', async () => {
    return getSettings()
  })

  ipcMain.handle('settings:set', async (_event, settings) => {
    console.log('[ipc] settings:set', Object.keys(settings))
    saveSettings(settings)
    return true
  })

  // ── Stats ────────────────────────────────────────────────────
  ipcMain.handle('stats:optimization', async () => {
    const { promptCache } = await import('./optimization/cache')
    const cacheStats = promptCache.getStats()
    // Rough dollar estimates based on token savings
    const tokenToDollar = 0.003 / 1000 // ~$3/1M tokens average
    return {
      cacheHits: cacheStats.hits,
      cacheSaved: cacheStats.tokensSaved * tokenToDollar,
      contextSaved: 0, // populated as tasks run
      compressionSaved: 0,
      routingSaved: 0
    }
  })

  // ── Ollama ───────────────────────────────────────────────────
  ipcMain.handle('ollama:check', async () => {
    try {
      const res = await fetch('http://localhost:11434/api/tags')
      const data = await res.json()
      return { available: true, models: data.models || [] }
    } catch {
      return { available: false, models: [] }
    }
  })

  // ── Auth (Supabase Cloud) ───────────────────────────────────
  ipcMain.handle('auth:signup', async (_event, data: { email: string; password: string }) => {
    return cloudClient.signup(data.email, data.password)
  })

  ipcMain.handle('auth:login', async (_event, data: { email: string; password: string }) => {
    return cloudClient.login(data.email, data.password)
  })

  ipcMain.handle('auth:logout', async () => {
    await cloudClient.logout()
    return { success: true }
  })

  ipcMain.handle('auth:status', async () => {
    return {
      isAuthenticated: cloudClient.isAuthenticated,
      user: cloudClient.currentUser,
      profile: cloudClient.currentProfile
    }
  })

  ipcMain.handle('auth:refreshProfile', async () => {
    await cloudClient.refreshProfile()
    return {
      isAuthenticated: cloudClient.isAuthenticated,
      user: cloudClient.currentUser,
      profile: cloudClient.currentProfile
    }
  })

  // ── Credits ─────────────────────────────────────────────────
  ipcMain.handle('credits:balance', async () => {
    return cloudClient.getBalance()
  })

  ipcMain.handle('credits:purchase', async (_event, amount: number) => {
    const result = await cloudClient.purchaseCredits(amount)
    if (result.checkout_url) {
      shell.openExternal(result.checkout_url)
    }
    return result
  })

  ipcMain.handle('credits:history', async () => {
    return cloudClient.getTransactionHistory()
  })

  // ── Cloud AI (Pro users) ────────────────────────────────────
  ipcMain.handle('cloud:chat', async (_event, params) => {
    const res = await cloudClient.chatCompletion(params)
    return res.json()
  })

  ipcMain.handle('cloud:classify', async (_event, prompt: string) => {
    return cloudClient.classify(prompt)
  })

  ipcMain.handle('cloud:validate', async (_event, params) => {
    return cloudClient.validate(params)
  })
}
