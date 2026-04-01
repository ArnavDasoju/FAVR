/**
 * VLM Validator — uses Gemini Flash (free) to analyze screenshots and code diffs.
 * This is the "eye" that decides if the agent's work looks correct.
 */

const GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta'

export interface VlmValidationResult {
  confidence: number // 0-100
  reasoning: string
  issues: string[]
}

/**
 * Validate agent output using Gemini Flash vision.
 * Compares before/after screenshots and analyzes the diff.
 */
export async function validateWithVlm(opts: {
  apiKey: string
  prompt: string // the original task
  beforeScreenshot: string | null // base64
  afterScreenshot: string | null // base64
  diff: string | null
  testOutput: string | null
  consoleErrors: string[]
}): Promise<VlmValidationResult> {
  const { apiKey, prompt, beforeScreenshot, afterScreenshot, diff, testOutput, consoleErrors } = opts

  const parts: Array<{ text: string } | { inlineData: { mimeType: string; data: string } }> = []

  // Build the validation prompt
  parts.push({
    text: buildValidationPrompt(prompt, diff, testOutput, consoleErrors)
  })

  // Add screenshots if available
  if (beforeScreenshot) {
    parts.push({ text: '\n\nBEFORE screenshot:' })
    parts.push({ inlineData: { mimeType: 'image/png', data: beforeScreenshot } })
  }

  if (afterScreenshot) {
    parts.push({ text: '\n\nAFTER screenshot (current state):' })
    parts.push({ inlineData: { mimeType: 'image/png', data: afterScreenshot } })
  }

  try {
    const response = await fetch(
      `${GEMINI_API_BASE}/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts }],
          generationConfig: {
            temperature: 0.1,
            maxOutputTokens: 1024
          }
        })
      }
    )

    if (!response.ok) {
      const errorBody = await response.text()
      console.error('[vlm] Gemini error:', response.status, errorBody)
      // Return low confidence on API error — forces human review
      return { confidence: 50, reasoning: `VLM unavailable: ${response.status}`, issues: ['VLM validation failed'] }
    }

    const data = await response.json()
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text ?? ''

    return parseVlmResponse(text)
  } catch (err) {
    console.error('[vlm] validation failed:', err)
    return { confidence: 50, reasoning: 'VLM validation error', issues: ['Could not reach Gemini API'] }
  }
}

function buildValidationPrompt(
  taskPrompt: string,
  diff: string | null,
  testOutput: string | null,
  consoleErrors: string[]
): string {
  const sections: string[] = []

  sections.push('You are a code review validator. Analyze whether the task was completed correctly.')
  sections.push('')
  sections.push(`TASK: ${taskPrompt}`)

  if (diff) {
    sections.push('')
    sections.push('CODE CHANGES (git diff):')
    sections.push('```diff')
    sections.push(diff.slice(0, 3000))
    sections.push('```')
  }

  if (testOutput) {
    sections.push('')
    sections.push('TEST OUTPUT:')
    sections.push('```')
    sections.push(testOutput.slice(-2000))
    sections.push('```')
  }

  if (consoleErrors.length > 0) {
    sections.push('')
    sections.push('CONSOLE ERRORS:')
    for (const err of consoleErrors.slice(0, 10)) {
      sections.push(`- ${err}`)
    }
  }

  sections.push('')
  sections.push('Respond in this exact JSON format:')
  sections.push('```json')
  sections.push('{')
  sections.push('  "confidence": <0-100>,')
  sections.push('  "reasoning": "<brief explanation>",')
  sections.push('  "issues": ["<issue 1>", "<issue 2>"]')
  sections.push('}')
  sections.push('```')
  sections.push('')
  sections.push('confidence: 90-100 = task completed correctly, 50-89 = partially done or minor issues, 0-49 = broken or wrong.')
  sections.push('If screenshots are provided, check that the visual output matches the task requirements.')

  return sections.join('\n')
}

function parseVlmResponse(text: string): VlmValidationResult {
  // Try to extract JSON from the response
  const jsonMatch = text.match(/\{[\s\S]*?\}/)
  if (jsonMatch) {
    try {
      const parsed = JSON.parse(jsonMatch[0])
      return {
        confidence: Math.max(0, Math.min(100, Number(parsed.confidence) || 50)),
        reasoning: String(parsed.reasoning || ''),
        issues: Array.isArray(parsed.issues) ? parsed.issues.map(String) : []
      }
    } catch {
      // Fall through to heuristic parsing
    }
  }

  // Heuristic fallback: look for confidence keywords
  const lower = text.toLowerCase()
  if (lower.includes('success') || lower.includes('correct') || lower.includes('completed')) {
    return { confidence: 85, reasoning: text.slice(0, 200), issues: [] }
  }
  if (lower.includes('error') || lower.includes('fail') || lower.includes('broken')) {
    return { confidence: 30, reasoning: text.slice(0, 200), issues: ['Agent output has errors'] }
  }

  return { confidence: 50, reasoning: text.slice(0, 200), issues: ['Could not parse VLM response'] }
}

/**
 * Quick validation without screenshots — just analyzes test output and diff.
 * Used when no dev server is configured.
 */
export async function validateTextOnly(opts: {
  apiKey: string
  prompt: string
  diff: string | null
  testOutput: string | null
}): Promise<VlmValidationResult> {
  return validateWithVlm({
    ...opts,
    beforeScreenshot: null,
    afterScreenshot: null,
    consoleErrors: []
  })
}
