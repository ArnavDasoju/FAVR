/**
 * Agent Manager — spawns agent processes, captures output, streams to UI.
 *
 * Supports:
 * - CLI agents (Claude, Ollama) via node-pty
 * - Cloud agents (OpenRouter) via HTTP streaming
 */

import { BrowserWindow } from 'electron'
import type { QueuedSubtask } from '../tasks/queue'
import { promptCache } from '../optimization/cache'
import { buildContextWindow, formatContextForPrompt } from '../optimization/context'

export type AgentProcessStatus = 'idle' | 'running' | 'validating' | 'error' | 'done'

export interface AgentProcess {
  id: string
  name: string
  model: string
  type: 'cli' | 'cloud' | 'local'
  status: AgentProcessStatus
  progress: number
  subtaskId: string | null
  projectDir: string | null
  outputLines: string[]
  pid: number | null
  startedAt: number | null
  abortController: AbortController | null
}

// Token budget per complexity
const TOKEN_BUDGETS: Record<string, number> = {
  low: 1000,
  medium: 4000,
  high: 8000
}

class AgentManager {
  private agents: Map<string, AgentProcess> = new Map()
  private openrouterKey: string | null = null
  private ollamaBaseUrl = 'http://localhost:11434'

  setOpenRouterKey(key: string) {
    this.openrouterKey = key
  }

  /**
   * Spawn an agent to execute a subtask.
   */
  async spawn(subtask: QueuedSubtask, projectDir: string): Promise<string> {
    const model = subtask.assignedModel ?? 'ollama/llama3'
    const agentId = subtask.assignedAgentId ?? crypto.randomUUID()
    const type = this.getAgentType(model)

    const agent: AgentProcess = {
      id: agentId,
      name: this.getAgentName(model),
      model,
      type,
      status: 'running',
      progress: 0,
      subtaskId: subtask.id,
      projectDir,
      outputLines: [],
      pid: null,
      startedAt: Date.now(),
      abortController: new AbortController()
    }

    this.agents.set(agentId, agent)
    this.emitStatus(agent)

    // Route to appropriate execution method
    try {
      if (type === 'local') {
        await this.runOllama(agent, subtask)
      } else if (type === 'cloud') {
        await this.runOpenRouter(agent, subtask)
      } else {
        await this.runCli(agent, subtask)
      }

      agent.status = 'done'
      agent.progress = 100
    } catch (err) {
      agent.status = 'error'
      this.appendOutput(agent, `ERROR: ${err instanceof Error ? err.message : String(err)}`)
    }

    this.emitStatus(agent)
    return agentId
  }

  /**
   * Run via Ollama local API.
   */
  private async runOllama(agent: AgentProcess, subtask: QueuedSubtask): Promise<void> {
    const modelName = agent.model.replace('ollama/', '')
    this.appendOutput(agent, `> Starting Ollama (${modelName})...`)
    this.appendOutput(agent, `> Project: ${agent.projectDir}`)
    this.appendOutput(agent, `> Task: ${subtask.prompt}`)
    agent.progress = 10

    const response = await fetch(`${this.ollamaBaseUrl}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: modelName,
        prompt: this.buildPrompt(subtask),
        stream: true
      }),
      signal: agent.abortController?.signal
    })

    if (!response.ok) {
      throw new Error(`Ollama error: ${response.status} ${response.statusText}`)
    }

    await this.streamNdjson(agent, response)
  }

  /**
   * Run via OpenRouter cloud API.
   */
  private async runOpenRouter(agent: AgentProcess, subtask: QueuedSubtask): Promise<void> {
    if (!this.openrouterKey) {
      throw new Error('OpenRouter API key not set')
    }

    this.appendOutput(agent, `> Starting ${agent.name}...`)
    this.appendOutput(agent, `> Model: ${agent.model}`)
    this.appendOutput(agent, `> Task: ${subtask.prompt}`)
    agent.progress = 10

    const maxTokens = TOKEN_BUDGETS[subtask.complexity] ?? 4000

    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.openrouterKey}`,
        'HTTP-Referer': 'https://bld.dev',
        'X-Title': 'BLD'
      },
      body: JSON.stringify({
        model: agent.model,
        messages: [
          { role: 'system', content: this.buildSystemPrompt(agent.projectDir) },
          { role: 'user', content: this.buildPrompt(subtask) }
        ],
        max_tokens: maxTokens,
        stream: true
      }),
      signal: agent.abortController?.signal
    })

    if (!response.ok) {
      const body = await response.text()
      throw new Error(`OpenRouter error: ${response.status} — ${body}`)
    }

    await this.streamSSE(agent, response)
  }

  /**
   * Run via CLI (for Claude Code, etc.) — uses child_process.
   */
  private async runCli(agent: AgentProcess, subtask: QueuedSubtask): Promise<void> {
    this.appendOutput(agent, `> Starting CLI agent: ${agent.model}`)
    this.appendOutput(agent, `> Task: ${subtask.prompt}`)
    agent.progress = 10

    // For now, CLI agents go through OpenRouter as well
    // In the future, this will spawn actual CLI processes (claude, cursor)
    if (this.openrouterKey) {
      await this.runOpenRouter(agent, subtask)
    } else {
      throw new Error('No API key available for CLI agent — set OpenRouter key or use Ollama')
    }
  }

  /**
   * Stream NDJSON responses (Ollama format).
   */
  private async streamNdjson(agent: AgentProcess, response: Response): Promise<void> {
    const reader = response.body?.getReader()
    if (!reader) return

    const decoder = new TextDecoder()
    let buffer = ''
    let totalTokens = 0

    while (true) {
      const { done, value } = await reader.read()
      if (done) break

      buffer += decoder.decode(value, { stream: true })
      const lines = buffer.split('\n')
      buffer = lines.pop() ?? ''

      for (const line of lines) {
        if (!line.trim()) continue
        try {
          const data = JSON.parse(line)
          if (data.response) {
            this.appendOutput(agent, data.response)
            totalTokens++
            agent.progress = Math.min(90, 10 + (totalTokens / 50) * 80)
            this.emitStatus(agent)
          }
        } catch {
          // Skip malformed lines
        }
      }
    }
  }

  /**
   * Stream SSE responses (OpenAI/OpenRouter format).
   */
  private async streamSSE(agent: AgentProcess, response: Response): Promise<void> {
    const reader = response.body?.getReader()
    if (!reader) return

    const decoder = new TextDecoder()
    let buffer = ''
    let fullOutput = ''
    let chunks = 0

    while (true) {
      const { done, value } = await reader.read()
      if (done) break

      buffer += decoder.decode(value, { stream: true })
      const lines = buffer.split('\n')
      buffer = lines.pop() ?? ''

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue
        const payload = line.slice(6).trim()
        if (payload === '[DONE]') continue

        try {
          const data = JSON.parse(payload)
          const content = data.choices?.[0]?.delta?.content
          if (content) {
            fullOutput += content
            chunks++

            // Emit output in line-sized chunks
            if (content.includes('\n')) {
              const outputLines = fullOutput.split('\n')
              fullOutput = outputLines.pop() ?? ''
              for (const outputLine of outputLines) {
                if (outputLine.trim()) {
                  this.appendOutput(agent, outputLine)
                }
              }
            }

            agent.progress = Math.min(90, 10 + (chunks / 100) * 80)
            this.emitStatus(agent)
          }
        } catch {
          // Skip malformed SSE
        }
      }
    }

    // Flush remaining output
    if (fullOutput.trim()) {
      this.appendOutput(agent, fullOutput)
    }
  }

  private buildSystemPrompt(projectDir: string | null): string {
    if (!projectDir) {
      return 'You are a coding agent. Execute the task precisely. Output only the code changes needed. Be concise.'
    }

    // Use cached project context for token savings
    const { systemMessage } = promptCache.getProjectContext(projectDir)
    return `You are a coding agent. Execute the task precisely. Output only the code changes needed. Be concise.\n\n${systemMessage}`
  }

  private buildPrompt(subtask: QueuedSubtask): string {
    return subtask.prompt
  }

  private appendOutput(agent: AgentProcess, line: string) {
    agent.outputLines.push(line)
    // Keep last 500 lines
    if (agent.outputLines.length > 500) {
      agent.outputLines = agent.outputLines.slice(-500)
    }
    this.emit('agent:output', { agentId: agent.id, line })
  }

  private emitStatus(agent: AgentProcess) {
    this.emit('agent:status', {
      agentId: agent.id,
      status: agent.status,
      progress: agent.progress,
      name: agent.name,
      model: agent.model,
      subtaskId: agent.subtaskId
    })
  }

  private getAgentType(model: string): 'cli' | 'cloud' | 'local' {
    if (model.startsWith('ollama/')) return 'local'
    if (model.startsWith('cli/')) return 'cli'
    return 'cloud'
  }

  private getAgentName(model: string): string {
    const nameMap: Record<string, string> = {
      'anthropic/claude-sonnet-4.6': 'Claude Sonnet',
      'openai/gpt-5.4': 'GPT-5.4',
      'deepseek/deepseek-chat': 'DeepSeek',
      'google/gemini-2.5-flash': 'Gemini Flash',
      'ollama/llama3': 'Ollama Llama3'
    }
    return nameMap[model] ?? model.split('/').pop() ?? model
  }

  /**
   * Kill a running agent.
   */
  kill(agentId: string) {
    const agent = this.agents.get(agentId)
    if (!agent) return

    agent.abortController?.abort()
    agent.status = 'error'
    agent.progress = 0
    this.appendOutput(agent, '> Agent killed by user.')
    this.emitStatus(agent)
  }

  getAgent(agentId: string): AgentProcess | undefined {
    return this.agents.get(agentId)
  }

  getAllAgents(): AgentProcess[] {
    return Array.from(this.agents.values()).map((a) => ({
      ...a,
      abortController: null // Don't serialize AbortController
    }))
  }

  private emit(channel: string, data: unknown) {
    const wins = BrowserWindow.getAllWindows()
    for (const win of wins) {
      win.webContents.send(channel, data)
    }
  }
}

// Singleton
export const agentManager = new AgentManager()
