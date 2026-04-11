import { app, BrowserWindow, shell } from 'electron'
import { join } from 'path'
import { setupTray } from './tray'
import { setupIpc } from './ipc'
import { taskQueue } from './tasks/queue'
import { agentManager } from './agents/manager'
import { modelRouter } from './optimization/router'
import { loadSettings } from './store'
import { cloudClient } from './cloud/supabase'

let mainWindow: BrowserWindow | null = null

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#0a0a0a',
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 16, y: 16 },
    show: false,
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      sandbox: false,
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: true
    }
  })

  mainWindow.on('ready-to-show', () => {
    mainWindow?.show()
  })

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url)
    return { action: 'deny' }
  })

  const isDev = !app.isPackaged
  if (isDev && process.env['ELECTRON_RENDERER_URL']) {
    mainWindow.loadURL(process.env['ELECTRON_RENDERER_URL'])
  } else {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'))
  }
}

async function checkOllama(): Promise<void> {
  try {
    const res = await fetch('http://localhost:11434/api/tags')
    if (res.ok) {
      modelRouter.setOllamaAvailable(true)
      console.log('[main] Ollama detected')
    }
  } catch {
    modelRouter.setOllamaAvailable(false)
  }
}

app.whenReady().then(() => {
  setupIpc()

  // Load persisted settings (API keys, thresholds, projects)
  loadSettings()

  // Initialize cloud client (Supabase auth + credit proxy)
  const supabaseUrl = process.env.SUPABASE_URL ?? ''
  const supabaseAnonKey = process.env.SUPABASE_ANON_KEY ?? ''
  if (supabaseUrl && supabaseAnonKey) {
    cloudClient.init(supabaseUrl, supabaseAnonKey)
    console.log('[main] Cloud client initialized')
  }

  // Wire queue → agent manager: spawn agent and return output + changed files
  taskQueue.setAgentSpawner(async (subtask, projectDir) => {
    const agentId = await agentManager.spawn(subtask, projectDir)
    const agent = agentManager.getAgent(agentId)
    return {
      agentId,
      output: agent?.outputLines ?? [],
      changedFiles: agent?.changedFiles ?? []
    }
  })

  // Check for Ollama on startup
  checkOllama()

  createWindow()
  setupTray(mainWindow!)

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow()
    }
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})
