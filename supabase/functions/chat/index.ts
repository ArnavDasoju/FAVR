/**
 * Chat Edge Function — OpenRouter proxy.
 *
 * Pro users hit this endpoint instead of calling OpenRouter directly.
 * BLD's master API key is used, and credits are deducted per request.
 *
 * Flow:
 * 1. Authenticate user via Supabase JWT
 * 2. Check credit balance
 * 3. Proxy request to OpenRouter with BLD's master key
 * 4. Stream response back to client
 * 5. After completion, calculate cost and deduct credits
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { corsHeaders } from '../_shared/cors.ts'

// Cost per 1M tokens (approximate, by model family)
const MODEL_COSTS: Record<string, { input: number; output: number }> = {
  'anthropic/claude-sonnet-4.6': { input: 3.0, output: 15.0 },
  'anthropic/claude-haiku-4.5': { input: 0.8, output: 4.0 },
  'openai/gpt-5.4': { input: 5.0, output: 15.0 },
  'openai/gpt-4.1-mini': { input: 0.4, output: 1.6 },
  'deepseek/deepseek-chat': { input: 0.14, output: 0.28 },
  'google/gemini-2.5-flash': { input: 0.0, output: 0.0 }, // Free tier
  'meta-llama/llama-3.3-70b-instruct': { input: 0.4, output: 0.4 },
}

// Default cost if model not in map
const DEFAULT_COST = { input: 2.0, output: 8.0 }

function estimateCost(model: string, inputTokens: number, outputTokens: number): number {
  const costs = MODEL_COSTS[model] ?? DEFAULT_COST
  return (inputTokens * costs.input + outputTokens * costs.output) / 1_000_000
}

Deno.serve(async (req: Request) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders })
  }

  try {
    // ── Auth ────────────────────────────────────────────────────
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'Missing authorization' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
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
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // ── Check tier + balance ────────────────────────────────────
    const { data: profile } = await supabase
      .from('profiles')
      .select('tier, credits')
      .eq('id', user.id)
      .single()

    if (!profile || profile.tier === 'free') {
      return new Response(JSON.stringify({ error: 'Pro subscription required' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (profile.credits <= 0) {
      return new Response(JSON.stringify({ error: 'Insufficient credits', balance: profile.credits }), {
        status: 402,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // ── Parse request ───────────────────────────────────────────
    const body = await req.json()
    const { model, messages, task_id, max_tokens, stream } = body

    if (!model || !messages) {
      return new Response(JSON.stringify({ error: 'Missing model or messages' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const openrouterKey = Deno.env.get('OPENROUTER_API_KEY')
    if (!openrouterKey) {
      return new Response(JSON.stringify({ error: 'Server configuration error' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // ── Proxy to OpenRouter ─────────────────────────────────────
    const orResponse = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${openrouterKey}`,
        'HTTP-Referer': 'https://bld.dev',
        'X-Title': 'BLD',
      },
      body: JSON.stringify({
        model,
        messages,
        max_tokens: max_tokens ?? 4000,
        stream: stream ?? false,
      }),
    })

    if (!orResponse.ok) {
      const errBody = await orResponse.text()
      return new Response(JSON.stringify({ error: 'OpenRouter error', detail: errBody }), {
        status: orResponse.status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // ── Streaming mode ──────────────────────────────────────────
    if (stream) {
      // For streaming, we proxy the SSE stream and deduct credits after
      const { readable, writable } = new TransformStream()
      const writer = writable.getWriter()
      const reader = orResponse.body!.getReader()
      const decoder = new TextDecoder()
      let totalOutput = 0

      // Stream in background, deduct credits when done
      ;(async () => {
        try {
          while (true) {
            const { done, value } = await reader.read()
            if (done) break
            await writer.write(value)

            // Count output tokens roughly from SSE chunks
            const text = decoder.decode(value, { stream: true })
            const lines = text.split('\n')
            for (const line of lines) {
              if (line.startsWith('data: ') && line !== 'data: [DONE]') {
                try {
                  const data = JSON.parse(line.slice(6))
                  if (data.choices?.[0]?.delta?.content) {
                    totalOutput += data.choices[0].delta.content.length / 4 // rough token estimate
                  }
                  // Check for usage in final chunk
                  if (data.usage) {
                    totalOutput = data.usage.completion_tokens ?? totalOutput
                  }
                } catch { /* skip */ }
              }
            }
          }
        } finally {
          await writer.close()

          // Estimate input tokens from messages
          const inputTokens = JSON.stringify(messages).length / 4
          const cost = estimateCost(model, inputTokens, totalOutput)

          // Deduct credits (fire and forget)
          const adminClient = createClient(
            Deno.env.get('SUPABASE_URL') ?? '',
            Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
          )
          await adminClient.rpc('deduct_credits', {
            p_user_id: user.id,
            p_amount: cost,
            p_task_id: task_id ?? null,
            p_description: `${model} — ${Math.round(inputTokens)}in/${Math.round(totalOutput)}out`,
          })

          // Update daily stats
          await adminClient.rpc('increment_daily_stat', {
            p_user_id: user.id,
            p_field: 'credits_spent',
            p_value: cost,
          })
          await adminClient.rpc('increment_daily_stat', {
            p_user_id: user.id,
            p_field: 'tokens_used',
            p_value: Math.round(inputTokens + totalOutput),
          })
        }
      })()

      return new Response(readable, {
        headers: {
          ...corsHeaders,
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
        },
      })
    }

    // ── Non-streaming mode ──────────────────────────────────────
    const result = await orResponse.json()
    const usage = result.usage ?? {}
    const inputTokens = usage.prompt_tokens ?? JSON.stringify(messages).length / 4
    const outputTokens = usage.completion_tokens ?? 0
    const cost = estimateCost(model, inputTokens, outputTokens)

    // Deduct credits
    const adminClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    )
    const deductResult = await adminClient.rpc('deduct_credits', {
      p_user_id: user.id,
      p_amount: cost,
      p_task_id: task_id ?? null,
      p_description: `${model} — ${inputTokens}in/${outputTokens}out`,
    })

    if (deductResult.data?.success === false) {
      return new Response(JSON.stringify({
        error: deductResult.data.error,
        balance: deductResult.data.balance,
      }), {
        status: 402,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Update daily stats
    await adminClient.rpc('increment_daily_stat', {
      p_user_id: user.id,
      p_field: 'credits_spent',
      p_value: cost,
    })
    await adminClient.rpc('increment_daily_stat', {
      p_user_id: user.id,
      p_field: 'tokens_used',
      p_value: Math.round(inputTokens + outputTokens),
    })

    return new Response(JSON.stringify({
      ...result,
      bld_cost: cost,
      bld_balance: deductResult.data?.balance,
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })

  } catch (err) {
    console.error('[chat] Error:', err)
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
