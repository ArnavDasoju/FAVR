import { ipcMain, dialog, BrowserWindow, shell } from 'electron'
import { taskQueue } from './tasks/queue'
import { agentManager } from './agents/manager'
import { getSettings, saveSettings, saveProject, removeProject as removePersistedProject } from './store'
import { cloudClient } from './cloud/supabase'
import { runAnalysis } from './engine/index'
import type { AnalysisResult } from './engine/types'
import { loadMeridianScenario } from './data/meridian-scenario'
import { parseDocuments } from './ingest/parser'
import { scanCodebase } from './ingest/scanner'

// Store the latest analysis result for quick access
let latestAnalysis: AnalysisResult | null = null

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

  ipcMain.handle('dialog:openFiles', async () => {
    const win = BrowserWindow.getFocusedWindow()
    if (!win) return null
    const result = await dialog.showOpenDialog(win, {
      properties: ['openFile', 'multiSelections'],
      filters: [
        { name: 'Documents', extensions: ['json', 'txt', 'md', 'csv', 'pdf'] },
        { name: 'All Files', extensions: ['*'] }
      ]
    })
    if (result.canceled || result.filePaths.length === 0) return null
    return result.filePaths
  })

  // ── FAVR Analysis Engine ────────────────────────────────────
  ipcMain.handle('analysis:loadDemo', async () => {
    const scenario = loadMeridianScenario()
    const emit = (channel: string, data: unknown) => {
      for (const win of BrowserWindow.getAllWindows()) {
        win.webContents.send(channel, data)
      }
    }

    try {
      const result = await runAnalysis({
        services: scenario.services,
        dependencies: scenario.dependencies,
        vulnerabilities: scenario.vulnerabilities,
        iterations: 5000,
        onProgress: (p) => emit('analysis:progress', p)
      })

      latestAnalysis = result
      emit('analysis:complete', serializeAnalysis(result))
      return serializeAnalysis(result)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      emit('analysis:error', msg)
      throw err
    }
  })

  ipcMain.handle('analysis:run', async (_event, data: {
    filePaths?: string[]
    codebasePath?: string
    iterations?: number
  }) => {
    const emit = (channel: string, data: unknown) => {
      for (const win of BrowserWindow.getAllWindows()) {
        win.webContents.send(channel, data)
      }
    }

    try {
      // Parse uploaded documents
      let parsedInput = { services: [] as any[], dependencies: [] as any[], vulnerabilities: [] as any[] }

      if (data.filePaths && data.filePaths.length > 0) {
        const parsed = parseDocuments(data.filePaths)
        parsedInput.services = parsed.services
        parsedInput.dependencies = parsed.dependencies
        parsedInput.vulnerabilities = parsed.vulnerabilities
        emit('analysis:progress', { phase: 'ingest', progress: 100, message: `Parsed ${parsed.rawDocuments.length} documents` })
      }

      // If no services/vulns parsed, fall back to demo data
      if (parsedInput.vulnerabilities.length === 0) {
        const scenario = loadMeridianScenario()
        parsedInput = {
          services: scenario.services,
          dependencies: scenario.dependencies,
          vulnerabilities: scenario.vulnerabilities
        }
      }

      // If codebase path provided, scan it
      if (data.codebasePath) {
        emit('analysis:progress', { phase: 'scan', progress: 0, message: 'Scanning codebase...' })
        const scanResults = scanCodebase(data.codebasePath, parsedInput.vulnerabilities)
        const found = scanResults.filter(r => r.found)
        emit('analysis:progress', { phase: 'scan', progress: 100, message: `Found ${found.length} vulnerabilities in codebase` })
      }

      // Run analysis
      const result = await runAnalysis({
        services: parsedInput.services,
        dependencies: parsedInput.dependencies,
        vulnerabilities: parsedInput.vulnerabilities,
        iterations: data.iterations ?? 5000,
        onProgress: (p) => emit('analysis:progress', p)
      })

      latestAnalysis = result
      emit('analysis:complete', serializeAnalysis(result))
      return serializeAnalysis(result)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      emit('analysis:error', msg)
      throw err
    }
  })

  ipcMain.handle('analysis:getLatest', async () => {
    return latestAnalysis ? serializeAnalysis(latestAnalysis) : null
  })

  ipcMain.handle('analysis:scan', async (_event, data: { codebasePath: string }) => {
    if (!latestAnalysis) throw new Error('Run analysis first')
    const results = scanCodebase(data.codebasePath, latestAnalysis.graph.vulnerabilities)
    return results
  })

  // ── Documents ───────────────────────────────────────────────
  ipcMain.handle('documents:parse', async (_event, filePaths: string[]) => {
    return parseDocuments(filePaths)
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

/**
 * Serialize AnalysisResult for IPC (Maps aren't serializable).
 */
function serializeAnalysis(result: AnalysisResult): any {
  return {
    ...result,
    graph: {
      services: result.graph.services,
      dependencies: result.graph.dependencies,
      vulnerabilities: result.graph.vulnerabilities
    }
  }
}
