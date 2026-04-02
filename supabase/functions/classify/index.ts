/**
 * Classify Edge Function — Task classification via Gemini Free.
 *
 * Takes a task prompt and returns:
 * - type (feature, bugfix, refactor, test, docs, style)
 * - complexity (low, medium, high)
 * - suggested_model
 * - reasoning
 * - subtasks (if decomposition needed)
 *
 * Uses Gemini Flash (free tier) so this costs nothing.
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { corsHeaders } from '../_shared/cors.ts'

const GEMINI_CLASSIFY_PROMPT = `You are a task classifier for a coding agent system. Analyze the given task and return a JSON object with:

{
  "type": "feature" | "bugfix" | "refactor" | "test" | "docs" | "style",
  "complexity": "low" | "medium" | "high",
  "suggested_model": "<model-id>",
  "reasoning": "<one sentence explaining classification>",
  "subtasks": [
    { "prompt": "<subtask description>", "type": "<type>", "complexity": "<complexity>", "suggested_model": "<model>" }
  ]
}

Model selection rules:
- "style" type or CSS/UI tasks → "anthropic/claude-haiku-4.5" (cheap, good for simple changes)
- "test" or "docs" → "deepseek/deepseek-chat" (cheap, capable)
- "bugfix" low complexity → "deepseek/deepseek-chat"
- "feature" or "refactor" high complexity → "anthropic/claude-sonnet-4.6"
- Default for medium complexity → "openai/gpt-4.1-mini"

Only create subtasks if the task is complex enough to warrant decomposition (medium/high).
Return ONLY valid JSON, no markdown.`

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders })
  }

  try {
    // Auth
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

    const { prompt } = await req.json()
    if (!prompt) {
      return new Response(JSON.stringify({ error: 'Missing prompt' }), {
        status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const geminiKey = Deno.env.get('GEMINI_API_KEY')
    if (!geminiKey) {
      // Fallback to heuristic classification
      return new Response(JSON.stringify(heuristicClassify(prompt)), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Call Gemini Flash (free)
    const geminiResponse = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${geminiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{
            parts: [
              { text: GEMINI_CLASSIFY_PROMPT },
              { text: `Task to classify: "${prompt}"` },
            ],
          }],
          generationConfig: {
            temperature: 0.1,
            maxOutputTokens: 1024,
          },
        }),
      }
    )

    if (!geminiResponse.ok) {
      console.error('[classify] Gemini error:', await geminiResponse.text())
      return new Response(JSON.stringify(heuristicClassify(prompt)), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const geminiResult = await geminiResponse.json()
    const text = geminiResult.candidates?.[0]?.content?.parts?.[0]?.text ?? ''

    // Extract JSON from response
    const jsonMatch = text.match(/\{[\s\S]*\}/)
    if (!jsonMatch) {
      return new Response(JSON.stringify(heuristicClassify(prompt)), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const classification = JSON.parse(jsonMatch[0])

    return new Response(JSON.stringify(classification), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })

  } catch (err) {
    console.error('[classify] Error:', err)
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})

function heuristicClassify(prompt: string) {
  const lower = prompt.toLowerCase()

  let type = 'feature'
  if (/\b(fix|bug|broken|error|issue|crash)\b/.test(lower)) type = 'bugfix'
  else if (/\b(refactor|clean|reorganize|restructure)\b/.test(lower)) type = 'refactor'
  else if (/\b(test|spec|coverage)\b/.test(lower)) type = 'test'
  else if (/\b(doc|readme|comment|jsdoc)\b/.test(lower)) type = 'docs'
  else if (/\b(style|css|color|font|layout|ui|design|theme|dark mode)\b/.test(lower)) type = 'style'

  const wordCount = prompt.split(/\s+/).length
  const complexity = wordCount > 30 ? 'high' : wordCount > 10 ? 'medium' : 'low'

  const modelMap: Record<string, string> = {
    style: 'anthropic/claude-haiku-4.5',
    test: 'deepseek/deepseek-chat',
    docs: 'deepseek/deepseek-chat',
    bugfix: complexity === 'high' ? 'anthropic/claude-sonnet-4.6' : 'deepseek/deepseek-chat',
    feature: complexity === 'high' ? 'anthropic/claude-sonnet-4.6' : 'openai/gpt-4.1-mini',
    refactor: 'anthropic/claude-sonnet-4.6',
  }

  return {
    type,
    complexity,
    suggested_model: modelMap[type] ?? 'openai/gpt-4.1-mini',
    reasoning: `Heuristic classification: ${type} (${complexity})`,
    subtasks: [],
  }
}
