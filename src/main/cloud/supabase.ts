/**
 * Supabase client for the main process.
 *
 * Handles auth (signup/login/logout), credit operations,
 * and cloud-mode agent execution (proxying through edge functions).
 */

import { BrowserWindow } from 'electron'
import { store } from '../store'

interface SupabaseSession {
  access_token: string
  refresh_token: string
  user: {
    id: string
    email: string
  }
  expires_at: number
}

interface Profile {
  tier: 'free' | 'pro' | 'pro_byok' | 'team'
  credits: number
  stripe_customer_id: string | null
}

class CloudClient {
  private session: SupabaseSession | null = null
  private profile: Profile | null = null
  private supabaseUrl: string = ''
  private supabaseAnonKey: string = ''

  /**
   * Initialize with Supabase credentials.
   */
  init(url: string, anonKey: string) {
    this.supabaseUrl = url
    this.supabaseAnonKey = anonKey

    // Restore session from persistent store
    const savedSession = store.get('supabaseSession' as any) as SupabaseSession | undefined
    if (savedSession && savedSession.expires_at > Date.now() / 1000) {
      this.session = savedSession
      this.refreshProfile().catch(() => {})
    }
  }

  get isAuthenticated(): boolean {
    return this.session !== null && this.session.expires_at > Date.now() / 1000
  }

  get currentUser() {
    return this.session?.user ?? null
  }

  get currentProfile() {
    return this.profile
  }

  get isProUser(): boolean {
    return this.profile?.tier === 'pro' || this.profile?.tier === 'team'
  }

  get creditBalance(): number {
    return this.profile?.credits ?? 0
  }

  // ── Auth ────────────────────────────────────────────────────

  async signup(email: string, password: string): Promise<{ success: boolean; error?: string }> {
    try {
      const res = await this.request('/auth/v1/signup', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
        headers: { apikey: this.supabaseAnonKey },
      })

      if (res.error) return { success: false, error: res.error.message ?? res.error }

      if (res.access_token) {
        await this.setSession(res)
        return { success: true }
      }

      // Email confirmation required
      return { success: true }
    } catch (err) {
      return { success: false, error: err instanceof Error ? err.message : 'Signup failed' }
    }
  }

  async login(email: string, password: string): Promise<{ success: boolean; error?: string }> {
    try {
      const res = await this.request('/auth/v1/token?grant_type=password', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
        headers: { apikey: this.supabaseAnonKey },
      })

      if (res.error) return { success: false, error: res.error_description ?? res.error }

      await this.setSession(res)
      return { success: true }
    } catch (err) {
      return { success: false, error: err instanceof Error ? err.message : 'Login failed' }
    }
  }

  async logout(): Promise<void> {
    if (this.session) {
      await this.request('/auth/v1/logout', {
        method: 'POST',
        headers: {
          apikey: this.supabaseAnonKey,
          Authorization: `Bearer ${this.session.access_token}`,
        },
      }).catch(() => {})
    }

    this.session = null
    this.profile = null
    store.delete('supabaseSession' as any)
    this.emitAuthChange()
  }

  async refreshToken(): Promise<boolean> {
    if (!this.session?.refresh_token) return false

    try {
      const res = await this.request('/auth/v1/token?grant_type=refresh_token', {
        method: 'POST',
        body: JSON.stringify({ refresh_token: this.session.refresh_token }),
        headers: { apikey: this.supabaseAnonKey },
      })

      if (res.access_token) {
        await this.setSession(res)
        return true
      }
      return false
    } catch {
      return false
    }
  }

  // ── Cloud AI proxy ──────────────────────────────────────────

  /**
   * Send a chat completion through BLD's cloud proxy.
   * This uses BLD's master OpenRouter key and deducts user credits.
   */
  async chatCompletion(params: {
    model: string
    messages: Array<{ role: string; content: string }>
    max_tokens?: number
    task_id?: string
    stream?: boolean
  }): Promise<Response> {
    await this.ensureAuth()

    const res = await fetch(`${this.supabaseUrl}/functions/v1/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.session!.access_token}`,
      },
      body: JSON.stringify(params),
    })

    return res
  }

  /**
   * Classify a task through the cloud function.
   */
  async classify(prompt: string): Promise<unknown> {
    await this.ensureAuth()

    const res = await fetch(`${this.supabaseUrl}/functions/v1/classify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.session!.access_token}`,
      },
      body: JSON.stringify({ prompt }),
    })

    return res.json()
  }

  /**
   * Validate task output through the cloud function.
   */
  async validate(params: {
    prompt: string
    diff?: string
    before_screenshot?: string
    after_screenshot?: string
    agent_output?: string
  }): Promise<unknown> {
    await this.ensureAuth()

    const res = await fetch(`${this.supabaseUrl}/functions/v1/validate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.session!.access_token}`,
      },
      body: JSON.stringify(params),
    })

    return res.json()
  }

  // ── Credits ─────────────────────────────────────────────────

  async getBalance(): Promise<{ balance: number; tier: string }> {
    await this.ensureAuth()

    const res = await fetch(`${this.supabaseUrl}/functions/v1/credits?action=balance`, {
      headers: { Authorization: `Bearer ${this.session!.access_token}` },
    })

    return res.json()
  }

  async purchaseCredits(amount: number): Promise<{ checkout_url?: string; error?: string }> {
    await this.ensureAuth()

    const res = await fetch(`${this.supabaseUrl}/functions/v1/credits?action=purchase`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.session!.access_token}`,
      },
      body: JSON.stringify({ amount }),
    })

    return res.json()
  }

  async getTransactionHistory(): Promise<{ transactions: unknown[] }> {
    await this.ensureAuth()

    const res = await fetch(`${this.supabaseUrl}/functions/v1/credits?action=history`, {
      headers: { Authorization: `Bearer ${this.session!.access_token}` },
    })

    return res.json()
  }

  // ── Profile ─────────────────────────────────────────────────

  async refreshProfile(): Promise<void> {
    if (!this.session) return

    const res = await this.request('/rest/v1/profiles?select=tier,credits,stripe_customer_id', {
      headers: {
        apikey: this.supabaseAnonKey,
        Authorization: `Bearer ${this.session.access_token}`,
      },
    })

    if (Array.isArray(res) && res.length > 0) {
      this.profile = res[0]
      this.emitAuthChange()
    }
  }

  // ── Internal ────────────────────────────────────────────────

  private async setSession(data: any): Promise<void> {
    this.session = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      user: {
        id: data.user?.id ?? '',
        email: data.user?.email ?? '',
      },
      expires_at: data.expires_at ?? (Date.now() / 1000 + 3600),
    }

    store.set('supabaseSession' as any, this.session)
    await this.refreshProfile()
    this.emitAuthChange()
  }

  private async ensureAuth(): Promise<void> {
    if (!this.session) {
      throw new Error('Not authenticated — sign in first')
    }

    // Refresh if expiring in next 5 minutes
    if (this.session.expires_at < Date.now() / 1000 + 300) {
      const refreshed = await this.refreshToken()
      if (!refreshed) {
        this.session = null
        this.profile = null
        this.emitAuthChange()
        throw new Error('Session expired — sign in again')
      }
    }
  }

  private async request(path: string, init: { method?: string; body?: string; headers?: Record<string, string> }) {
    const url = `${this.supabaseUrl}${path}`
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(init.headers ?? {}),
    }

    const res = await fetch(url, { method: init.method, body: init.body, headers })
    return res.json()
  }

  private emitAuthChange() {
    const wins = BrowserWindow.getAllWindows()
    for (const win of wins) {
      win.webContents.send('auth:changed', {
        isAuthenticated: this.isAuthenticated,
        user: this.currentUser,
        profile: this.currentProfile,
      })
    }
  }
}

export const cloudClient = new CloudClient()
