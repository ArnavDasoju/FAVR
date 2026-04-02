/**
 * Credits Edge Function — Credit management + Stripe integration.
 *
 * Endpoints (via action field):
 * - balance: Get current credit balance
 * - purchase: Create Stripe checkout session for credit purchase
 * - webhook: Handle Stripe webhook (payment confirmation → add credits)
 * - history: Get transaction history
 *
 * Credit Economics (user buys $50):
 * - Stripe fee (2.9%): -$1.45
 * - BLD cut (22.5%): -$10.92
 * - OpenRouter fee (5.5%): -$2.08
 * - User gets: $35.57 in credits
 *
 * Effective credit rate: ~71.1% of purchase price
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { corsHeaders } from '../_shared/cors.ts'

const CREDIT_RATE = 0.711 // User gets 71.1% of purchase as credits
const STRIPE_API = 'https://api.stripe.com/v1'

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders })
  }

  try {
    const url = new URL(req.url)
    const action = url.searchParams.get('action') ?? 'balance'

    // Stripe webhook doesn't have auth header — uses signature verification
    if (action === 'webhook') {
      return handleWebhook(req)
    }

    // All other actions require auth
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

    switch (action) {
      case 'balance':
        return getBalance(user.id)
      case 'purchase':
        return createCheckout(user.id, await req.json())
      case 'history':
        return getHistory(user.id)
      default:
        return new Response(JSON.stringify({ error: 'Unknown action' }), {
          status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
    }
  } catch (err) {
    console.error('[credits] Error:', err)
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})

// ── Balance ─────────────────────────────────────────────────────
async function getBalance(userId: string) {
  const admin = getAdminClient()
  const { data: profile } = await admin
    .from('profiles')
    .select('credits, tier')
    .eq('id', userId)
    .single()

  if (!profile) {
    return jsonResponse({ error: 'Profile not found' }, 404)
  }

  return jsonResponse({
    balance: profile.credits,
    tier: profile.tier,
  })
}

// ── Purchase (create Stripe checkout) ───────────────────────────
async function createCheckout(userId: string, body: { amount: number }) {
  const stripeKey = Deno.env.get('STRIPE_SECRET_KEY')
  if (!stripeKey) {
    return jsonResponse({ error: 'Stripe not configured' }, 500)
  }

  const { amount } = body
  if (!amount || ![20, 50, 100].includes(amount)) {
    return jsonResponse({ error: 'Invalid amount. Choose $20, $50, or $100.' }, 400)
  }

  const admin = getAdminClient()
  const { data: profile } = await admin
    .from('profiles')
    .select('stripe_customer_id, email')
    .eq('id', userId)
    .single()

  if (!profile) return jsonResponse({ error: 'Profile not found' }, 404)

  // Create or reuse Stripe customer
  let customerId = profile.stripe_customer_id
  if (!customerId) {
    const customerRes = await stripeRequest(stripeKey, '/customers', {
      email: profile.email,
      metadata: { bld_user_id: userId },
    })
    customerId = customerRes.id

    await admin
      .from('profiles')
      .update({ stripe_customer_id: customerId })
      .eq('id', userId)
  }

  const creditsGranted = (amount * CREDIT_RATE).toFixed(2)

  // Create checkout session
  const session = await stripeRequest(stripeKey, '/checkout/sessions', {
    customer: customerId,
    mode: 'payment',
    'line_items[0][price_data][currency]': 'usd',
    'line_items[0][price_data][product_data][name]': `BLD Credits — $${creditsGranted}`,
    'line_items[0][price_data][product_data][description]': `$${amount} purchase → $${creditsGranted} in AI credits`,
    'line_items[0][price_data][unit_amount]': String(amount * 100), // cents
    'line_items[0][quantity]': '1',
    'metadata[bld_user_id]': userId,
    'metadata[credits_amount]': creditsGranted,
    'metadata[purchase_amount]': String(amount),
    success_url: 'bld://credits/success',
    cancel_url: 'bld://credits/cancel',
  })

  return jsonResponse({ checkout_url: session.url, session_id: session.id })
}

// ── Transaction History ─────────────────────────────────────────
async function getHistory(userId: string) {
  const admin = getAdminClient()
  const { data: transactions } = await admin
    .from('credit_transactions')
    .select('*')
    .eq('user_id', userId)
    .order('created_at', { ascending: false })
    .limit(50)

  return jsonResponse({ transactions: transactions ?? [] })
}

// ── Stripe Webhook ──────────────────────────────────────────────
async function handleWebhook(req: Request) {
  const stripeKey = Deno.env.get('STRIPE_SECRET_KEY')
  const webhookSecret = Deno.env.get('STRIPE_WEBHOOK_SECRET')

  if (!stripeKey || !webhookSecret) {
    return jsonResponse({ error: 'Stripe not configured' }, 500)
  }

  const body = await req.text()
  const signature = req.headers.get('stripe-signature')

  if (!signature) {
    return jsonResponse({ error: 'Missing stripe-signature' }, 400)
  }

  // Verify webhook signature
  const isValid = await verifyStripeSignature(body, signature, webhookSecret)
  if (!isValid) {
    return jsonResponse({ error: 'Invalid signature' }, 400)
  }

  const event = JSON.parse(body)

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object
    const userId = session.metadata?.bld_user_id
    const creditsAmount = parseFloat(session.metadata?.credits_amount ?? '0')
    const purchaseAmount = parseFloat(session.metadata?.purchase_amount ?? '0')

    if (!userId || creditsAmount <= 0) {
      console.error('[webhook] Invalid metadata:', session.metadata)
      return jsonResponse({ received: true })
    }

    const admin = getAdminClient()

    // Add credits
    const result = await admin.rpc('add_credits', {
      p_user_id: userId,
      p_amount: creditsAmount,
      p_type: 'purchase',
      p_stripe_payment_id: session.payment_intent,
      p_description: `Purchased $${purchaseAmount} → $${creditsAmount.toFixed(2)} credits`,
    })

    if (result.data?.success) {
      // Ensure user is Pro tier
      await admin
        .from('profiles')
        .update({ tier: 'pro' })
        .eq('id', userId)
        .eq('tier', 'free') // Only upgrade from free
    }

    console.log(`[webhook] Added $${creditsAmount} credits for user ${userId}`)
  }

  return jsonResponse({ received: true })
}

// ── Helpers ─────────────────────────────────────────────────────

function getAdminClient() {
  return createClient(
    Deno.env.get('SUPABASE_URL') ?? '',
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
  )
}

function jsonResponse(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  })
}

async function stripeRequest(key: string, path: string, params: Record<string, string>) {
  const body = new URLSearchParams(params).toString()
  const res = await fetch(`${STRIPE_API}${path}`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${key}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  })
  if (!res.ok) {
    const err = await res.text()
    throw new Error(`Stripe error ${res.status}: ${err}`)
  }
  return res.json()
}

async function verifyStripeSignature(payload: string, signature: string, secret: string): Promise<boolean> {
  // Parse the signature header
  const elements = signature.split(',')
  const timestampEl = elements.find(e => e.startsWith('t='))
  const signatureEl = elements.find(e => e.startsWith('v1='))

  if (!timestampEl || !signatureEl) return false

  const timestamp = timestampEl.split('=')[1]
  const expectedSig = signatureEl.split('=')[1]

  // Compute expected signature
  const signedPayload = `${timestamp}.${payload}`
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const mac = await crypto.subtle.sign('HMAC', key, encoder.encode(signedPayload))
  const computedSig = Array.from(new Uint8Array(mac))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')

  // Constant-time comparison
  if (computedSig.length !== expectedSig.length) return false
  let result = 0
  for (let i = 0; i < computedSig.length; i++) {
    result |= computedSig.charCodeAt(i) ^ expectedSig.charCodeAt(i)
  }
  return result === 0
}
