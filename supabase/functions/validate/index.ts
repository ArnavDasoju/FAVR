/**
 * Validate Edge Function — VLM validation via Gemini Free.
 *
 * Takes before/after screenshots, the task prompt, and diff,
 * returns a confidence score with reasoning.
 *
 * Uses Gemini Flash vision (free tier) so this costs nothing.
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { corsHeaders } from '../_shared/cors.ts'

const VALIDATION_PROMPT = `You are a visual QA validator for a coding agent system. You will be given:
1. The original task description
2. A code diff showing what was changed
3. Optionally, before/after screenshots

Analyze whether the task was completed correctly. Return a JSON object:

{
  "confidence": <0-100>,
  "reasoning": "<detailed explanation of what you see>",
  "issues": ["<issue 1>", "<issue 2>"],
  "suggestion": "<what to fix if confidence < 85>"
}

Scoring guide:
- 90-100: Task clearly completed, no visible issues
- 70-89: Mostly done, minor issues
- 40-69: Partially done, significant issues
- 0-39: Not done or broken

Return ONLY valid JSON, no markdown.`

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders })
  }

  try {
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'Missing authorization' }), {
        status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      { global: { headers: { Authorization: authHeader } } }
    )

    const { data: { user }, error: authError } = await supabase.auth.getUser()
    if (authError || !user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const body = await req.json()
    const { prompt, diff, before_screenshot, after_screenshot, agent_output } = body

    if (!prompt) {
      return new Response(JSON.stringify({ error: 'Missing prompt' }), {
        status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const geminiKey = Deno.env.get('GEMINI_API_KEY')
    if (!geminiKey) {
      return new Response(JSON.stringify(heuristicValidate(prompt, diff, agent_output)), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Build parts for Gemini
    const parts: Array<{ text?: string; inlineData?: { mimeType: string; data: string } }> = [
      { text: VALIDATION_PROMPT },
      { text: `\nTask: "${prompt}"` },
    ]

    if (diff) {
      parts.push({ text: `\nCode diff:\n\`\`\`\n${diff.slice(0, 8000)}\n\`\`\`` })
    }

    if (agent_output) {
      parts.push({ text: `\nAgent output (last 2000 chars):\n${agent_output.slice(-2000)}` })
    }

    // Add screenshots as inline images if provided
    if (before_screenshot) {
      const imageData = before_screenshot.replace(/^data:image\/\w+;base64,/, '')
      parts.push({
        text: '\nBefore screenshot:',
      })
      parts.push({
        inlineData: { mimeType: 'image/png', data: imageData },
      })
    }

    if (after_screenshot) {
      const imageData = after_screenshot.replace(/^data:image\/\w+;base64,/, '')
      parts.push({
        text: '\nAfter screenshot:',
      })
      parts.push({
        inlineData: { mimeType: 'image/png', data: imageData },
      })
    }

    const geminiResponse = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${geminiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts }],
          generationConfig: {
            temperature: 0.1,
            maxOutputTokens: 1024,
          },
        }),
      }
    )

    if (!geminiResponse.ok) {
      console.error('[validate] Gemini error:', await geminiResponse.text())
      return new Response(JSON.stringify(heuristicValidate(prompt, diff, agent_output)), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const geminiResult = await geminiResponse.json()
    const text = geminiResult.candidates?.[0]?.content?.parts?.[0]?.text ?? ''

    const jsonMatch = text.match(/\{[\s\S]*\}/)
    if (!jsonMatch) {
      return new Response(JSON.stringify(heuristicValidate(prompt, diff, agent_output)), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const validation = JSON.parse(jsonMatch[0])

    return new Response(JSON.stringify(validation), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })

  } catch (err) {
    console.error('[validate] Error:', err)
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})

function heuristicValidate(prompt: string, diff?: string, agentOutput?: string) {
  let confidence = 50
  const issues: string[] = []

  if (!diff && !agentOutput) {
    return { confidence: 10, reasoning: 'No output or diff to validate', issues: ['No changes detected'], suggestion: 'Agent may not have produced output' }
  }

  if (diff) {
    const lines = diff.split('\n')
    const additions = lines.filter((l: string) => l.startsWith('+')).length
    const deletions = lines.filter((l: string) => l.startsWith('-')).length
    if (additions > 0) confidence += 15
    if (additions > 5) confidence += 10
    if (deletions > 0 && additions > deletions) confidence += 5
  }

  if (agentOutput) {
    const lower = agentOutput.toLowerCase()
    if (lower.includes('error') || lower.includes('failed')) {
      confidence -= 20
      issues.push('Agent output contains error indicators')
    }
    if (lower.includes('done') || lower.includes('complete') || lower.includes('success')) {
      confidence += 10
    }
  }

  confidence = Math.max(0, Math.min(100, confidence))

  return {
    confidence,
    reasoning: `Heuristic validation (no Gemini key): scored ${confidence}% based on diff size and output keywords`,
    issues,
    suggestion: confidence < 85 ? 'Manual review recommended — heuristic validation only' : null,
  }
}
