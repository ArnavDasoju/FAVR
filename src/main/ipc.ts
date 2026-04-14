import { ipcMain, dialog, BrowserWindow, shell } from 'electron'
import { writeFileSync } from 'fs'
import { execSync } from 'child_process'
import { taskQueue, type QueuedSubtask } from './tasks/queue'
import { agentManager } from './agents/manager'
import { modelRouter } from './optimization/router'
import { getSettings, saveSettings, saveProject, removeProject as removePersistedProject } from './store'
import { cloudClient } from './cloud/supabase'
import { runAnalysis, runWhatIf, generateReport } from './engine/index'
import { buildAttackGraph } from './engine/attack-graph'
import type { Vulnerability, AnalysisResult, WhatIfConstraints } from './engine/types'
import type { ScanSnapshot } from './ingest/codebase-analyzer'
import { loadMeridianScenario } from './data/meridian-scenario'
import { LOG4J_SERVICES, LOG4J_DEPENDENCIES, LOG4J_VULNERABILITIES } from './data/log4j-benchmark'
import { setCalibration, getCalibration, type RiskModel } from './engine/calibration'
import { parseDocuments } from './ingest/parser'
import { scanCodebase } from './ingest/scanner'
import { analyzeCodebase } from './ingest/codebase-analyzer'
import {
  saveScanResult, listScanHistory, getProjectHistory,
  loadScanResult, getLatestSnapshot, deleteScanResult, clearScanHistory
} from './ingest/scan-history'
import { getFreshness, clearVulnCache } from './ingest/vuln-data-pipeline'
import { optimizeAgentAssignments } from './optimization/budget-optimizer'
import { agentStatsTracker } from './optimization/agent-stats'
import { WorkspaceSession, getActiveSession, setActiveSession } from './agents/workspace-session'

// Store the latest analysis result for quick access
let latestAnalysis: AnalysisResult | null = null

// Stash reference created at the start of a fix-all run — used by fix:undo
let fixSessionStash: { cwd: string; created: boolean } | null = null

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

      // If no services/vulns parsed, tell the user to upload files or use demo
      if (parsedInput.vulnerabilities.length === 0) {
        throw new Error(
          'No vulnerabilities found in uploaded documents. ' +
          'Please upload JSON CVE feeds, vendor advisories, or service configs. ' +
          'Or click "Load Demo Scenario" to try with sample data.'
        )
      }

      // If codebase path provided, scan it
      if (data.codebasePath) {
        emit('analysis:progress', { phase: 'scan', progress: 0, message: 'Scanning codebase...' })
        const scanResults = scanCodebase(data.codebasePath, parsedInput.vulnerabilities)
        const found = scanResults.filter(r => r.found)
        emit('analysis:progress', { phase: 'scan', progress: 100, message: `Found ${found.length} vulnerabilities in codebase` })
      }

      // Auto-generate stub services for any service IDs referenced by vulns but not defined
      const existingServiceIds = new Set(parsedInput.services.map((s: any) => s.id))
      const referencedIds = new Set<string>()
      for (const vuln of parsedInput.vulnerabilities) {
        for (const sid of vuln.affectedServiceIds) {
          if (!existingServiceIds.has(sid)) referencedIds.add(sid)
        }
      }

      // Infer tier from vulnerability severity: if a service has critical vulns, it's likely critical
      const serviceTiers = new Map<string, 'critical' | 'high' | 'medium' | 'low'>()
      const tierRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }
      for (const vuln of parsedInput.vulnerabilities) {
        for (const sid of vuln.affectedServiceIds) {
          const current = serviceTiers.get(sid) ?? 'low'
          if ((tierRank[vuln.severity] ?? 1) > (tierRank[current] ?? 1)) {
            serviceTiers.set(sid, vuln.severity)
          }
        }
      }

      // Collect tech stack from affected packages
      const serviceTechStacks = new Map<string, string[]>()
      for (const vuln of parsedInput.vulnerabilities) {
        for (const sid of vuln.affectedServiceIds) {
          const stack = serviceTechStacks.get(sid) ?? []
          if (vuln.affectedPackage && vuln.affectedPackage !== 'unknown') {
            stack.push(vuln.affectedPackage)
          }
          serviceTechStacks.set(sid, stack)
        }
      }

      for (const sid of referencedIds) {
        parsedInput.services.push({
          id: sid,
          name: sid.replace(/-/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase()),
          techStack: [...new Set(serviceTechStacks.get(sid) ?? [])],
          tier: serviceTiers.get(sid) ?? 'medium' as const,
          sla: serviceTiers.get(sid) === 'critical' ? 99.99 : serviceTiers.get(sid) === 'high' ? 99.9 : 99.5,
          description: `Auto-generated from uploaded vulnerability data`,
          baseCompromiseProbability: 0,
          currentRiskScore: 0,
          complianceFrameworks: [],
          maintenanceWindow: null
        })
      }

      // Auto-generate dependencies between services if none were provided.
      // Infer: services sharing vulnerabilities are likely connected;
      // auth/api/gateway services are likely depended upon by others.
      if (parsedInput.dependencies.length === 0 && parsedInput.services.length > 1) {
        const serviceIds = parsedInput.services.map((s: any) => s.id)
        const addedDeps = new Set<string>()

        // Find auth/gateway services — other services likely depend on them
        const authIds = serviceIds.filter((id: string) => /auth|gateway|identity/.test(id))
        const apiIds = serviceIds.filter((id: string) => /api|backend|server/.test(id))

        for (const sid of serviceIds) {
          // Non-auth services depend on auth services
          for (const authId of authIds) {
            if (sid !== authId) {
              const key = `${sid}->${authId}`
              if (!addedDeps.has(key)) {
                parsedInput.dependencies.push({
                  from: sid, to: authId,
                  type: 'auth' as const,
                  propagationWeight: 0.3,
                  description: `${sid} depends on ${authId} for authentication`
                })
                addedDeps.add(key)
              }
            }
          }
        }

        // Portal/frontend services depend on API services
        const portalIds = serviceIds.filter((id: string) => /portal|frontend|web|admin|ui|dashboard/.test(id))
        for (const portalId of portalIds) {
          for (const apiId of apiIds) {
            if (portalId !== apiId) {
              const key = `${portalId}->${apiId}`
              if (!addedDeps.has(key)) {
                parsedInput.dependencies.push({
                  from: portalId, to: apiId,
                  type: 'api' as const,
                  propagationWeight: 0.25,
                  description: `${portalId} calls ${apiId}`
                })
                addedDeps.add(key)
              }
            }
          }
        }

        // Services sharing the same vulnerability are likely connected via shared-lib
        for (const vuln of parsedInput.vulnerabilities) {
          const sids = vuln.affectedServiceIds
          for (let a = 0; a < sids.length; a++) {
            for (let b = a + 1; b < sids.length; b++) {
              const key = `${sids[a]}->${sids[b]}`
              const reverseKey = `${sids[b]}->${sids[a]}`
              if (!addedDeps.has(key) && !addedDeps.has(reverseKey)) {
                parsedInput.dependencies.push({
                  from: sids[a], to: sids[b],
                  type: 'shared-lib' as const,
                  propagationWeight: 0.2,
                  description: `Shared dependency: ${vuln.affectedPackage}`
                })
                addedDeps.add(key)
              }
            }
          }
        }
      }

      // Run analysis
      const result = await runAnalysis({
        services: parsedInput.services,
        dependencies: parsedInput.dependencies,
        vulnerabilities: parsedInput.vulnerabilities,
        iterations: data.iterations,
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

  // ── Risk Model Configuration ─────────────────────────────────
  ipcMain.handle('analysis:setRiskModel', async (_event, model: RiskModel) => {
    return setCalibration(model)
  })

  ipcMain.handle('analysis:getRiskModel', async () => {
    return getCalibration()
  })

  // ── Log4j Benchmark (validation scenario) ────────────────────
  ipcMain.handle('analysis:loadBenchmark', async () => {
    const emit = (channel: string, data: unknown) => {
      for (const win of BrowserWindow.getAllWindows()) {
        win.webContents.send(channel, data)
      }
    }

    const result = await runAnalysis({
      services: LOG4J_SERVICES,
      dependencies: LOG4J_DEPENDENCIES,
      vulnerabilities: LOG4J_VULNERABILITIES,
      iterations: 5000,
      onProgress: (p) => emit('analysis:progress', p)
    })

    latestAnalysis = result
    return serializeAnalysis(result)
  })

  ipcMain.handle('analysis:scan', async (_event, data: { codebasePath: string }) => {
    if (!latestAnalysis) throw new Error('Run analysis first')
    const results = scanCodebase(data.codebasePath, latestAnalysis.graph.vulnerabilities)
    return results
  })

  // ── Codebase Auto-Analysis (no demo, no uploads needed) ───
  ipcMain.handle('analysis:analyzeCodebase', async (_event, data: {
    codebasePath: string
    iterations?: number
    incremental?: boolean
    timeoutMs?: number
  }) => {
    const emit = (channel: string, payload: unknown) => {
      for (const win of BrowserWindow.getAllWindows()) {
        win.webContents.send(channel, payload)
      }
    }

    try {
      // Get previous scan snapshot for incremental scanning
      let previousScan: ScanSnapshot | null = null
      if (data.incremental !== false) {
        previousScan = getLatestSnapshot(data.codebasePath)
      }

      // Phase 1-3: Discover services, dependencies, vulnerabilities from real codebase
      const codebaseResult = await analyzeCodebase({
        projectDir: data.codebasePath,
        onProgress: (p) => emit('analysis:progress', p),
        timeoutMs: data.timeoutMs,
        previousScan
      }) as any // _snapshot is attached

      if (codebaseResult.vulnerabilities.length === 0) {
        emit('analysis:progress', {
          phase: 'discovery',
          progress: 100,
          message: `Found ${codebaseResult.services.length} services and ${codebaseResult.stats.packagesScanned} packages — no known vulnerabilities detected.`
        })
        throw new Error(
          `Scanned ${codebaseResult.stats.packagesScanned} packages across ${codebaseResult.services.length} service(s) but found no known vulnerabilities. ` +
          `Ecosystems: ${codebaseResult.stats.ecosystems.join(', ')}. The codebase looks clean!`
        )
      }

      // Run the full FAVR analysis engine on the discovered data
      const result = await runAnalysis({
        services: codebaseResult.services,
        dependencies: codebaseResult.dependencies,
        vulnerabilities: codebaseResult.vulnerabilities,
        iterations: data.iterations,
        onProgress: (p) => emit('analysis:progress', p)
      })

      latestAnalysis = result

      // Save to scan history
      const projectName = data.codebasePath.split(/[/\\]/).pop() ?? 'unknown'
      saveScanResult({
        projectPath: data.codebasePath,
        projectName,
        timestamp: Date.now(),
        durationMs: codebaseResult.stats.scanDurationMs,
        stats: codebaseResult.stats,
        analysisJson: JSON.stringify(serializeAnalysis(result)),
        snapshot: codebaseResult._snapshot ?? {
          timestamp: Date.now(),
          projectDir: data.codebasePath,
          fileHashes: {},
          cachedCveData: {}
        }
      })

      emit('analysis:complete', serializeAnalysis(result))
      return {
        analysis: serializeAnalysis(result),
        stats: codebaseResult.stats
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      emit('analysis:error', msg)
      throw err
    }
  })

  // ── Scan History ──────────────────────────────────────────
  ipcMain.handle('scanHistory:list', async () => {
    return listScanHistory()
  })

  ipcMain.handle('scanHistory:projectHistory', async (_event, projectPath: string) => {
    return getProjectHistory(projectPath)
  })

  ipcMain.handle('scanHistory:load', async (_event, scanId: string) => {
    const entry = loadScanResult(scanId)
    if (!entry) throw new Error(`Scan not found: ${scanId}`)

    // Restore as the latest analysis
    try {
      const parsed = JSON.parse(entry.analysisJson)
      latestAnalysis = parsed
      const emit = (channel: string, payload: unknown) => {
        for (const win of BrowserWindow.getAllWindows()) {
          win.webContents.send(channel, payload)
        }
      }
      emit('analysis:complete', parsed)
      return { analysis: parsed, stats: entry.stats }
    } catch (err) {
      throw new Error('Failed to parse saved scan data')
    }
  })

  ipcMain.handle('scanHistory:delete', async (_event, scanId: string) => {
    return deleteScanResult(scanId)
  })

  ipcMain.handle('scanHistory:clear', async () => {
    clearScanHistory()
    return true
  })

  // ── Vulnerability Data Freshness ────────────────────────────
  ipcMain.handle('vuln:getFreshness', async () => {
    return getFreshness()
  })

  ipcMain.handle('vuln:clearCache', async () => {
    clearVulnCache()
    return true
  })

  // ── What-If Scenarios ────────────────────────────────────────
  ipcMain.handle('analysis:whatIf', async (_event, constraints: WhatIfConstraints) => {
    if (!latestAnalysis) throw new Error('Run analysis first')

    // Rebuild graph for what-if (needs adjacency maps)
    const graph = buildAttackGraph(
      latestAnalysis.graph.services.map(s => ({ ...s })),
      latestAnalysis.graph.dependencies.map(d => ({ ...d })),
      latestAnalysis.graph.vulnerabilities.map(v => ({ ...v, constraints: (v as any).constraints ?? [] }))
    )

    return runWhatIf(graph, latestAnalysis.simulation.optimalOrder, constraints)
  })

  // ── Report Export ──────────────────────────────────────────
  ipcMain.handle('analysis:exportReport', async () => {
    if (!latestAnalysis) throw new Error('Run analysis first')

    const win = BrowserWindow.getFocusedWindow()
    if (!win) return null

    const html = generateReport(latestAnalysis)

    const result = await dialog.showSaveDialog(win, {
      title: 'Export FAVR Report',
      defaultPath: `FAVR-Report-${new Date().toISOString().split('T')[0]}.html`,
      filters: [
        { name: 'HTML Report', extensions: ['html'] }
      ]
    })

    if (result.canceled || !result.filePath) return null

    writeFileSync(result.filePath, html, 'utf-8')
    shell.showItemInFolder(result.filePath)
    return result.filePath
  })

  // ── Fix-All (agents patch vulnerabilities in Monte-Carlo optimal order) ───
  ipcMain.handle('fix:all', async (_event, data: { codebasePath: string }) => {
    if (!latestAnalysis) throw new Error('Run a scan first')
    if (!data.codebasePath) throw new Error('Codebase path required')

    const { codebasePath } = data
    const vulns = latestAnalysis.graph.vulnerabilities
    const order = latestAnalysis.simulation.optimalOrder
    const services = latestAnalysis.graph.services

    const emit = (channel: string, payload: unknown) => {
      for (const win of BrowserWindow.getAllWindows()) {
        win.webContents.send(channel, payload)
      }
    }

    // Safety net: stash current working tree so "Undo" restores it
    fixSessionStash = null
    try {
      const porcelain = execSync('git status --porcelain', { cwd: codebasePath, encoding: 'utf-8' }).trim()
      if (porcelain.length > 0) {
        execSync('git stash push -u -m "favr-fix-all-backup"', { cwd: codebasePath, encoding: 'utf-8' })
        fixSessionStash = { cwd: codebasePath, created: true }
      } else {
        // Clean tree — nothing to stash, but we can still undo by reverting subsequent changes
        fixSessionStash = { cwd: codebasePath, created: false }
      }
    } catch (err) {
      console.warn('[fix:all] git not available — running without undo safety net:', err)
    }

    emit('fix:started', {
      total: order.length,
      canUndo: fixSessionStash !== null && fixSessionStash.created
    })

    const results: { cveId: string; success: boolean; error?: string; agentId?: string }[] = []

    for (let i = 0; i < order.length; i++) {
      const vulnId = order[i]
      // optimalOrder contains internal vuln ids (e.g. "vuln-001"), not CVE ids
      const vuln = vulns.find(v => v.id === vulnId) ?? vulns.find(v => v.cveId === vulnId)
      if (!vuln) {
        results.push({ cveId: vulnId, success: false, error: 'vuln not found in analysis' })
        emit('fix:vulnDone', { index: i, cveId: vulnId, success: false, error: 'vuln not found' })
        continue
      }
      const cveId = vuln.cveId

      const serviceNames = vuln.affectedServiceIds
        .map(id => services.find(s => s.id === id)?.name)
        .filter((n): n is string => !!n)

      // Classify vuln and route to the best-fit agent
      const routing = modelRouter.routeVuln(vuln)
      const model = routing.model
      const prompt = buildFixPrompt(vuln, serviceNames)

      const subtask: QueuedSubtask = {
        id: crypto.randomUUID(),
        parentId: `fix-${cveId}`,
        prompt,
        originalPrompt: prompt,
        taskType: 'general',
        complexity: vuln.complexity,
        suggestedModel: null,
        assignedModel: model,
        assignedAgentId: null,
        status: 'running',
        retryCount: 0,
        maxRetries: 0,
        confidence: null,
        error: null,
        createdAt: Date.now(),
        startedAt: Date.now(),
        completedAt: null,
        gitBranch: null,
        gitOriginalBranch: null,
        gitStashed: false
      }

      emit('fix:vulnStart', {
        index: i,
        cveId,
        title: vuln.title,
        affectedPackage: vuln.affectedPackage,
        patchedVersion: vuln.patchedVersion,
        severity: vuln.severity,
        complexity: vuln.complexity,
        model,
        displayName: routing.displayName,
        provider: routing.provider,
        taskType: routing.taskType,
        reasoning: routing.reasoning
      })

      try {
        const agentId = await agentManager.spawn(subtask, codebasePath)
        const agent = agentManager.getAgent(agentId)
        const success = agent?.status === 'done'
        const changedFiles = agent?.changedFiles ?? []
        results.push({ cveId, success, agentId })
        emit('fix:vulnDone', {
          index: i,
          cveId,
          success,
          agentId,
          changedFiles,
          error: success ? undefined : (agent?.outputLines.slice(-3).join(' ') ?? 'agent failed')
        })
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err)
        results.push({ cveId, success: false, error: msg })
        emit('fix:vulnDone', { index: i, cveId, success: false, error: msg })
      }
    }

    emit('fix:complete', {
      total: order.length,
      succeeded: results.filter(r => r.success).length,
      failed: results.filter(r => !r.success).length,
      canUndo: fixSessionStash !== null && fixSessionStash.created
    })

    return { results }
  })

  ipcMain.handle('fix:undo', async () => {
    if (!fixSessionStash) {
      throw new Error('Nothing to undo — no fix session active')
    }
    const { cwd, created } = fixSessionStash

    try {
      // Drop any files the agents wrote back to their pre-fix state
      execSync('git checkout -- .', { cwd, encoding: 'utf-8' })
      execSync('git clean -fd', { cwd, encoding: 'utf-8' })

      // Restore the stash we made at the start of the run (if any)
      if (created) {
        execSync('git stash pop', { cwd, encoding: 'utf-8' })
      }

      fixSessionStash = null
      return { success: true }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      throw new Error(`Undo failed: ${msg}`)
    }
  })

  // ── Budget Optimizer & Agent Stats ─────────────────────────
  ipcMain.handle('optimizer:preview', async (_event, data: { budget: number; maxConcurrent: number; preferFree: boolean }) => {
    if (!latestAnalysis) throw new Error('Run a scan first')

    const vulns = latestAnalysis.graph.vulnerabilities as unknown as import('./engine/types').Vulnerability[]
    const order = latestAnalysis.simulation.optimalOrder
    const stats = agentStatsTracker.getAllStats()
    const models = modelRouter.getModels()

    const result = optimizeAgentAssignments(
      vulns,
      order,
      {
        maxBudget: data.budget,
        maxConcurrentAgents: data.maxConcurrent,
        preferFree: data.preferFree
      },
      stats,
      models
    )

    return result
  })

  ipcMain.handle('agentStats:getAll', async () => {
    return agentStatsTracker.getAllStats()
  })

  ipcMain.handle('agentStats:getLeaderboard', async () => {
    return agentStatsTracker.getLeaderboard()
  })

  ipcMain.handle('agentStats:getHistory', async (_event, model: string, limit?: number) => {
    return agentStatsTracker.getHistory(model, limit)
  })

  ipcMain.handle('agentStats:reset', async () => {
    agentStatsTracker.reset()
    return { success: true }
  })

  // ── Remediation Workspace ─────────────────────────────────

  ipcMain.handle('workspace:start', async (_event, data: {
    codebasePath: string
    budget: number
    maxConcurrent: number
    preferFree: boolean
  }) => {
    if (!latestAnalysis) throw new Error('Run a scan first')
    if (!data.codebasePath) throw new Error('Codebase path required')
    if (getActiveSession()?.getStatus() === 'running') {
      throw new Error('A workspace session is already running — cancel it first')
    }

    const vulns = latestAnalysis.graph.vulnerabilities as unknown as Vulnerability[]
    const services = latestAnalysis.graph.services as unknown as import('./engine/types').Service[]
    const order = latestAnalysis.simulation.optimalOrder
    const stats = agentStatsTracker.getAllStats()
    const models = modelRouter.getModels()

    // Run optimizer
    const optimization = optimizeAgentAssignments(
      vulns, order,
      { maxBudget: data.budget, maxConcurrentAgents: data.maxConcurrent, preferFree: data.preferFree },
      stats, models
    )

    if (optimization.assignments.length === 0) {
      throw new Error('No vulnerabilities could be assigned within budget')
    }

    // Git safety: stash current working tree
    fixSessionStash = null
    try {
      const porcelain = execSync('git status --porcelain', { cwd: data.codebasePath, encoding: 'utf-8' }).trim()
      if (porcelain.length > 0) {
        execSync('git stash push -u -m "favr-workspace-backup"', { cwd: data.codebasePath, encoding: 'utf-8' })
        fixSessionStash = { cwd: data.codebasePath, created: true }
      } else {
        fixSessionStash = { cwd: data.codebasePath, created: false }
      }
    } catch (err) {
      console.warn('[workspace] git not available — running without undo safety net:', err)
    }

    // Create and run session
    const session = new WorkspaceSession({
      codebasePath: data.codebasePath,
      totalBudget: data.budget,
      maxConcurrent: data.maxConcurrent,
      assignments: optimization.assignments,
      skippedVulns: optimization.skippedVulns.map(s => s.vulnId),
      vulns,
      services
    })

    setActiveSession(session)

    // Run in background — don't block the IPC response
    session.run().then(finalState => {
      console.log(`[workspace] Session ${finalState.sessionId} complete: ${finalState.results.filter(r => r.success).length}/${finalState.results.length} succeeded, $${finalState.spent.toFixed(4)} spent`)
    }).catch(err => {
      console.error('[workspace] Session failed:', err)
    })

    return {
      sessionId: session.getState().sessionId,
      assignments: optimization.assignments,
      totalEstimatedCost: optimization.totalEstimatedCost,
      expectedFixRate: optimization.expectedFixRate,
      skippedVulns: optimization.skippedVulns,
      savingsVsNaive: optimization.savingsVsNaive
    }
  })

  ipcMain.handle('workspace:pause', async () => {
    const session = getActiveSession()
    if (!session) throw new Error('No active workspace session')
    session.pause()
    return { sessionId: session.getState().sessionId, status: 'paused' }
  })

  ipcMain.handle('workspace:resume', async () => {
    const session = getActiveSession()
    if (!session) throw new Error('No active workspace session')
    session.resume()
    return { sessionId: session.getState().sessionId, status: 'running' }
  })

  ipcMain.handle('workspace:cancel', async () => {
    const session = getActiveSession()
    if (!session) throw new Error('No active workspace session')
    session.cancel()
    return { sessionId: session.getState().sessionId, status: 'cancelled' }
  })

  ipcMain.handle('workspace:retry', async (_event, data: { vulnId: string; model?: string }) => {
    const session = getActiveSession()
    if (!session) throw new Error('No active workspace session')
    session.retryVuln(data.vulnId, data.model)
    return { vulnId: data.vulnId }
  })

  ipcMain.handle('workspace:state', async () => {
    const session = getActiveSession()
    if (!session) return null
    return session.getState()
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
 * Build a patch prompt for one vulnerability. Tells the agent which package to
 * bump, to what version, and asks it to fix calling code if the upgrade has
 * breaking changes. Uses the FILE: marker format so file-applier picks up edits.
 */
function buildFixPrompt(vuln: Vulnerability, serviceNames: string[]): string {
  const [pkgName, currentVersion] = vuln.affectedPackage.split('@')
  const patchedParts = (vuln.patchedVersion ?? '').split('@')
  const targetVersion = patchedParts.length > 1 ? patchedParts.slice(1).join('@') : 'latest safe version'
  const serviceHint = serviceNames.length > 0
    ? ` in service(s): ${serviceNames.join(', ')}`
    : ''

  return `Patch vulnerability ${vuln.cveId} — ${vuln.title}

Package: ${pkgName}
Current version: ${currentVersion ?? 'unknown'}
Target version: ${targetVersion}
Severity: ${vuln.severity} (CVSS ${vuln.cvssScore})${serviceHint}

Details:
${vuln.description}

Your task:
1. Find the dependency manifest (package.json, requirements.txt, go.mod, Cargo.toml, pom.xml, or Gemfile) in this project that depends on "${pkgName}".
2. Update that dependency to version "${targetVersion}".
3. If the upgrade has known breaking changes, also update any calling code in the project that uses the affected package so it matches the new API.
4. Do not touch files unrelated to this vulnerability.

Output every file you modify using this exact format, one block per file:

FILE: <relative/path/to/file>
\`\`\`
<full updated file contents>
\`\`\`
`
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
