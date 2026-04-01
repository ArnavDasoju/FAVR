/**
 * Conversation Compression — after N turns, compress older messages
 * into a summary to save tokens on long-running agent conversations.
 *
 * Uses Gemini Flash (free) to generate the summary, so compression itself costs nothing.
 */

const GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta'

export interface ConversationMessage {
  role: 'system' | 'user' | 'assistant'
  content: string
  tokens?: number
}

export interface CompressionResult {
  messages: ConversationMessage[]
  tokensBefore: number
  tokensAfter: number
  tokensSaved: number
  compressed: boolean
}

// Default: compress after this many turns
const DEFAULT_COMPRESS_AFTER = 10

// Keep this many recent messages uncompressed
const KEEP_RECENT = 4

/**
 * Compress a conversation if it exceeds the turn threshold.
 * Replaces older messages with a compact summary.
 */
export async function compressConversation(opts: {
  messages: ConversationMessage[]
  geminiApiKey: string | null
  compressAfter?: number
}): Promise<CompressionResult> {
  const { messages, geminiApiKey, compressAfter = DEFAULT_COMPRESS_AFTER } = opts

  const tokensBefore = messages.reduce((sum, m) => sum + estimateTokens(m.content), 0)

  // Not enough messages to compress
  if (messages.length <= compressAfter) {
    return { messages, tokensBefore, tokensAfter: tokensBefore, tokensSaved: 0, compressed: false }
  }

  // Split: system messages stay, old messages get compressed, recent stay
  const systemMessages = messages.filter((m) => m.role === 'system')
  const nonSystem = messages.filter((m) => m.role !== 'system')

  if (nonSystem.length <= KEEP_RECENT) {
    return { messages, tokensBefore, tokensAfter: tokensBefore, tokensSaved: 0, compressed: false }
  }

  const toCompress = nonSystem.slice(0, -KEEP_RECENT)
  const toKeep = nonSystem.slice(-KEEP_RECENT)

  // Generate summary
  let summary: string
  if (geminiApiKey) {
    summary = await generateSummary(toCompress, geminiApiKey)
  } else {
    summary = heuristicSummary(toCompress)
  }

  const summaryMessage: ConversationMessage = {
    role: 'user',
    content: `[Conversation summary — ${toCompress.length} earlier messages compressed]\n\n${summary}`
  }

  const compressed = [...systemMessages, summaryMessage, ...toKeep]
  const tokensAfter = compressed.reduce((sum, m) => sum + estimateTokens(m.content), 0)

  return {
    messages: compressed,
    tokensBefore,
    tokensAfter,
    tokensSaved: tokensBefore - tokensAfter,
    compressed: true
  }
}

/**
 * Use Gemini Flash (free) to generate a conversation summary.
 */
async function generateSummary(
  messages: ConversationMessage[],
  apiKey: string
): Promise<string> {
  const conversationText = messages
    .map((m) => `${m.role}: ${m.content}`)
    .join('\n\n')
    .slice(0, 8000) // Limit input to Gemini

  try {
    const response = await fetch(
      `${GEMINI_API_BASE}/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{
            parts: [{
              text: `Summarize this coding conversation concisely. Focus on:
1. What task was being worked on
2. What changes were made (files, functions, logic)
3. What issues were encountered
4. Current state of the work

Conversation:
${conversationText}

Provide a compact summary (under 500 words):`
            }]
          }],
          generationConfig: { temperature: 0.1, maxOutputTokens: 600 }
        })
      }
    )

    if (!response.ok) {
      return heuristicSummary(messages)
    }

    const data = await response.json()
    return data.candidates?.[0]?.content?.parts?.[0]?.text ?? heuristicSummary(messages)
  } catch {
    return heuristicSummary(messages)
  }
}

/**
 * Fallback: heuristic summary when no LLM is available.
 * Extracts key information from messages without AI.
 */
function heuristicSummary(messages: ConversationMessage[]): string {
  const parts: string[] = []

  // Extract file references
  const files = new Set<string>()
  const errors: string[] = []
  const actions: string[] = []

  for (const msg of messages) {
    // Find file paths
    const fileMatches = msg.content.match(/[\w./]+\.(ts|tsx|js|jsx|css|json|md)/g)
    if (fileMatches) fileMatches.forEach((f) => files.add(f))

    // Find errors
    if (msg.content.toLowerCase().includes('error')) {
      const errorLine = msg.content.split('\n').find((l) => l.toLowerCase().includes('error'))
      if (errorLine) errors.push(errorLine.trim().slice(0, 100))
    }

    // Extract first line of assistant messages as actions
    if (msg.role === 'assistant') {
      const firstLine = msg.content.split('\n')[0].trim()
      if (firstLine.length > 10 && firstLine.length < 200) {
        actions.push(firstLine)
      }
    }
  }

  if (files.size > 0) {
    parts.push(`Files touched: ${[...files].slice(0, 10).join(', ')}`)
  }
  if (actions.length > 0) {
    parts.push(`Actions taken: ${actions.slice(-5).join('; ')}`)
  }
  if (errors.length > 0) {
    parts.push(`Errors encountered: ${errors.slice(-3).join('; ')}`)
  }

  return parts.join('\n') || 'Previous conversation context (no extractable details).'
}

/**
 * Track diff-based updates — only send changed content on subsequent turns.
 */
export function buildDiffUpdate(
  previousContent: string,
  currentContent: string,
  filePath: string
): string | null {
  if (previousContent === currentContent) return null

  const prevLines = previousContent.split('\n')
  const currLines = currentContent.split('\n')

  const changes: string[] = []
  const maxLines = Math.max(prevLines.length, currLines.length)

  for (let i = 0; i < maxLines; i++) {
    if (prevLines[i] !== currLines[i]) {
      if (prevLines[i] !== undefined) changes.push(`- ${prevLines[i]}`)
      if (currLines[i] !== undefined) changes.push(`+ ${currLines[i]}`)
    }
  }

  if (changes.length === 0) return null
  if (changes.length > 50) {
    // Too many changes — just send the whole file
    return null
  }

  return `Changes to ${filePath}:\n\`\`\`diff\n${changes.join('\n')}\n\`\`\``
}

function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4)
}
