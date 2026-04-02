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
import { cloudClient } from '../cloud/supabase'
import { applyLlmOutput } from './file-applier'

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
  changedFiles: string[]
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
      changedFiles: [],
      pid: null,
      startedAt: Date.now(),
      abortController: new AbortController()
    }

    this.agents.set(agentId, agent)
    this.emitStatus(agent)

    // Route to appropriate execution method
    // Pro users (Credits model) → route cloud models through Supabase edge function
    // BYOK users → route directly to OpenRouter with their own key
    // Local models → always go through Ollama directly
    try {
      if (type === 'local') {
        await this.runOllama(agent, subtask)
      } else if (cloudClient.isAuthenticated && cloudClient.isProUser) {
        await this.runCloud(agent, subtask)
      } else if (type === 'cloud') {
        await this.runOpenRouter(agent, subtask)
      } else {
        await this.runCli(agent, subtask)
      }

      // Apply file changes from LLM output to the project directory
      if (agent.projectDir) {
        const fullOutput = agent.outputLines.join('\n')
        console.log('[agent-manager] Full output for file-applier:\n---\n' + fullOutput.slice(0, 2000) + '\n---')
        const appliedFiles = applyLlmOutput(agent.projectDir, fullOutput, subtask.originalPrompt ?? subtask.prompt)
        agent.changedFiles = appliedFiles
        if (appliedFiles.length > 0) {
          this.appendOutput(agent, `\n> Applied changes to ${appliedFiles.length} file(s):`)
          for (const f of appliedFiles) {
            this.appendOutput(agent, `>   ${f}`)
          }
        } else {
          this.appendOutput(agent, '> No file changes detected in output')
        }
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
   * Run via BLD cloud proxy (for Pro/Credits users).
   * Routes through Supabase edge function → uses BLD's master OpenRouter key.
   * Credits are deducted server-side.
   */
  private async runCloud(agent: AgentProcess, subtask: QueuedSubtask): Promise<void> {
    this.appendOutput(agent, `> Starting ${agent.name} (Cloud/Credits)...`)
    this.appendOutput(agent, `> Model: ${agent.model}`)
    this.appendOutput(agent, `> Task: ${subtask.prompt}`)
    this.appendOutput(agent, `> Credits mode — using BLD proxy`)
    agent.progress = 10

    const maxTokens = TOKEN_BUDGETS[subtask.complexity] ?? 4000

    const response = await cloudClient.chatCompletion({
      model: agent.model,
      messages: [
        { role: 'system', content: this.buildSystemPrompt(agent.projectDir) },
        { role: 'user', content: this.buildPrompt(subtask) }
      ],
      max_tokens: maxTokens,
      task_id: subtask.parentId,
      stream: true
    })

    if (!response.ok) {
      const body = await response.text()
      // Surface credit-specific errors to the user
      if (response.status === 402) {
        throw new Error('Insufficient credits — purchase more in the Credits tab')
      }
      if (response.status === 403) {
        throw new Error('Pro subscription required for cloud models')
      }
      throw new Error(`Cloud proxy error: ${response.status} — ${body}`)
    }

    // Stream SSE response (same format as OpenRouter)
    await this.streamSSE(agent, response)

    // Refresh credit balance after completion
    cloudClient.refreshProfile().catch(() => {})
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
   * Ollama streams token-by-token, so we accumulate into complete lines.
   */
  private async streamNdjson(agent: AgentProcess, response: Response): Promise<void> {
    const reader = response.body?.getReader()
    if (!reader) return

    const decoder = new TextDecoder()
    let buffer = ''
    let fullOutput = ''
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
            fullOutput += data.response
            totalTokens++

            // Emit complete lines to the UI as they form
            if (data.response.includes('\n')) {
              const outputLines = fullOutput.split('\n')
              fullOutput = outputLines.pop() ?? ''
              for (const outputLine of outputLines) {
                if (outputLine.trim()) {
                  this.appendOutput(agent, outputLine)
                }
              }
            }

            agent.progress = Math.min(90, 10 + (totalTokens / 50) * 80)
            this.emitStatus(agent)
          }
        } catch {
          // Skip malformed lines
        }
      }
    }

    // Flush remaining output
    if (fullOutput.trim()) {
      this.appendOutput(agent, fullOutput)
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
    const coreInstructions = `You are a coding agent. You create and modify files.

You MUST output file changes using EXACTLY this format — no other format will work:

FILE: index.js
\`\`\`
console.log("hello");
\`\`\`

Rules:
1. Write FILE: then the filename, then a code block with the FULL file contents.
2. Do NOT explain anything before or after. Just output FILE: blocks.
3. One FILE: block per file.
4. Use relative paths like index.js or src/app.ts.
5. Output ONLY FILE: blocks. No other text.

Example task: "create a hello world express server"
Example output:

FILE: index.js
\`\`\`
const express = require("express");
const app = express();
app.get("/", (req, res) => res.send("Hello World"));
app.listen(3000);
\`\`\`

FILE: package.json
\`\`\`
{ "name": "app", "dependencies": { "express": "^4.18.0" } }
\`\`\``

    if (!projectDir) {
      return coreInstructions
    }

    // Use cached project context for token savings
    const { systemMessage } = promptCache.getProjectContext(projectDir)
    return `${coreInstructions}\n\n${systemMessage}`
  }

  private buildPrompt(subtask: QueuedSubtask): string {
    const task = subtask.prompt

    // Build file listing for context
    let fileContext = ''
    const agent = Array.from(this.agents.values()).find((a) => a.subtaskId === subtask.id)
    if (agent?.projectDir) {
      try {
        const { execSync } = require('child_process')
        const tree = execSync(
          'find . -type f -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/dist/*" -not -path "*/out/*" -not -path "*/.next/*" | head -100',
          { cwd: agent.projectDir, encoding: 'utf-8', timeout: 5000 }
        )
        if (tree.trim()) {
          fileContext = `\n\nExisting project files:\n${tree.trim()}`
        }
      } catch {
        // Ignore
      }
    }

    // Wrap the task with explicit format instructions in the user message
    // Small models (Llama3) ignore system prompts but follow user message instructions
    return `Task: ${task}${fileContext}

IMPORTANT: Output ONLY in this exact format. No explanations. No markdown. No shell commands.

FILE: filename.ext
\`\`\`
full file contents here
\`\`\`

Start your response with "FILE:" immediately.`
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
      abortController: null // Don't serialize
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
