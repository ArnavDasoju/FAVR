import { useEffect, useState } from 'react'
import { useAuthStore } from '../stores/authStore'
import { useCreditsStore } from '../stores/creditsStore'

export default function Credits() {
  const { isAuthenticated, user, profile, login, signup, logout, loading, error, refreshStatus } =
    useAuthStore()
  const { balance, transactions, fetchBalance, fetchHistory, purchase } = useCreditsStore()

  const [authMode, setAuthMode] = useState<'login' | 'signup'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [purchaseLoading, setPurchaseLoading] = useState(false)

  useEffect(() => {
    refreshStatus()
  }, [])

  useEffect(() => {
    if (isAuthenticated) {
      fetchBalance()
      fetchHistory()
    }
  }, [isAuthenticated])

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault()
    if (authMode === 'login') {
      await login(email, password)
    } else {
      await signup(email, password)
    }
  }

  const handlePurchase = async (amount: number) => {
    setPurchaseLoading(true)
    const result = await purchase(amount)
    setPurchaseLoading(false)
    if (result.error) {
      alert(result.error)
    }
    // checkout_url is opened in browser by main process
  }

  // ── Not authenticated — show login/signup ───────────────────
  if (!isAuthenticated) {
    return (
      <div className="h-full flex flex-col px-6 pb-6 overflow-y-auto">
        <div className="mb-6">
          <h1 className="text-xl font-bold text-white mb-1">Credits</h1>
          <p className="text-sm text-surface-500">
            Sign in to purchase credits and use cloud AI models
          </p>
        </div>

        <div className="max-w-md">
          <div className="bg-surface-900 border border-surface-800 rounded-card p-6">
            <div className="flex gap-4 mb-6">
              <button
                onClick={() => setAuthMode('login')}
                className={`text-sm font-bold pb-1 border-b-2 transition-colors ${
                  authMode === 'login'
                    ? 'text-white border-white'
                    : 'text-surface-500 border-transparent hover:text-surface-300'
                }`}
              >
                Sign In
              </button>
              <button
                onClick={() => setAuthMode('signup')}
                className={`text-sm font-bold pb-1 border-b-2 transition-colors ${
                  authMode === 'signup'
                    ? 'text-white border-white'
                    : 'text-surface-500 border-transparent hover:text-surface-300'
                }`}
              >
                Sign Up
              </button>
            </div>

            <form onSubmit={handleAuth} className="flex flex-col gap-4">
              <div>
                <label className="text-[10px] font-bold text-surface-500 uppercase tracking-wider block mb-1.5">
                  Email
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input-field w-full"
                  placeholder="you@email.com"
                  required
                />
              </div>
              <div>
                <label className="text-[10px] font-bold text-surface-500 uppercase tracking-wider block mb-1.5">
                  Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input-field w-full"
                  placeholder="Min 6 characters"
                  minLength={6}
                  required
                />
              </div>

              {error && (
                <p className="text-xs text-red-400">{error}</p>
              )}

              <button
                type="submit"
                disabled={loading}
                className="bg-white text-black font-bold text-sm py-2.5 rounded-md hover:bg-surface-200 transition-colors disabled:opacity-50"
              >
                {loading ? 'Loading...' : authMode === 'login' ? 'Sign In' : 'Create Account'}
              </button>
            </form>

            <div className="mt-6 pt-4 border-t border-surface-800">
              <p className="text-xs text-surface-500">
                {authMode === 'login'
                  ? 'Free tier includes Ollama (local models). Pro unlocks cloud AI via credits.'
                  : 'Create an account to get $5 in free monthly credits with Pro.'}
              </p>
            </div>
          </div>

          {/* BYOK notice */}
          <div className="mt-4 bg-surface-900 border border-surface-800 rounded-card p-4">
            <p className="text-xs text-surface-500">
              <span className="text-white font-bold">Using BYOK?</span> You don't need an account.
              Add your API keys in Settings and agents will use them directly.
            </p>
          </div>
        </div>
      </div>
    )
  }

  // ── Authenticated — show credits dashboard ──────────────────
  const tier = profile?.tier ?? 'free'
  const isPro = tier === 'pro' || tier === 'team'

  return (
    <div className="h-full flex flex-col px-6 pb-6 overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-white mb-1">Credits</h1>
          <p className="text-sm text-surface-500">
            {user?.email} &middot;{' '}
            <span className="uppercase font-bold text-surface-400">{tier}</span>
          </p>
        </div>
        <button
          onClick={logout}
          className="text-xs text-surface-500 hover:text-white transition-colors"
        >
          Sign Out
        </button>
      </div>

      {/* Balance card */}
      <div className="bg-surface-900 border border-surface-800 rounded-card p-6 mb-6">
        <span className="text-[10px] font-bold text-surface-500 uppercase tracking-wider block mb-2">
          Credit Balance
        </span>
        <div className="flex items-baseline gap-2 mb-4">
          <span className="text-4xl font-bold text-white">${balance.toFixed(2)}</span>
          {!isPro && (
            <span className="text-xs text-surface-500">Free tier — Ollama only</span>
          )}
        </div>

        {isPro && (
          <div className="flex gap-3">
            {[20, 50, 100].map((amount) => (
              <button
                key={amount}
                onClick={() => handlePurchase(amount)}
                disabled={purchaseLoading}
                className="bg-surface-800 hover:bg-surface-700 text-white font-bold text-sm px-4 py-2 rounded-md transition-colors disabled:opacity-50"
              >
                + ${amount}
              </button>
            ))}
          </div>
        )}

        {!isPro && (
          <button
            onClick={() => handlePurchase(20)}
            disabled={purchaseLoading}
            className="bg-white text-black font-bold text-sm px-6 py-2.5 rounded-md hover:bg-surface-200 transition-colors disabled:opacity-50"
          >
            Upgrade to Pro — $20/mo + credits
          </button>
        )}
      </div>

      {/* Credit economics */}
      {isPro && (
        <div className="bg-surface-900 border border-surface-800 rounded-card p-5 mb-6">
          <span className="text-[10px] font-bold text-surface-500 uppercase tracking-[0.2em] block mb-3">
            How Credits Work
          </span>
          <div className="grid grid-cols-3 gap-4 text-center">
            <div>
              <span className="text-lg font-bold text-white block">You Pay</span>
              <span className="text-xs text-surface-500">Purchase amount</span>
            </div>
            <div>
              <span className="text-lg font-bold text-white block">71.1%</span>
              <span className="text-xs text-surface-500">Goes to AI credits</span>
            </div>
            <div>
              <span className="text-lg font-bold text-white block">$0</span>
              <span className="text-xs text-surface-500">Classification & validation</span>
            </div>
          </div>
        </div>
      )}

      {/* Recent transactions */}
      <div className="bg-surface-900 border border-surface-800 rounded-card p-5">
        <span className="text-[10px] font-bold text-surface-500 uppercase tracking-[0.2em] block mb-4">
          Recent Transactions
        </span>

        {transactions.length === 0 ? (
          <p className="text-sm text-surface-500">No transactions yet.</p>
        ) : (
          <div className="flex flex-col">
            {transactions.slice(0, 20).map((tx) => (
              <div
                key={tx.id}
                className="flex items-center gap-3 py-2.5 border-b border-surface-800/30 last:border-0"
              >
                <span
                  className={`text-xs font-bold w-16 shrink-0 ${
                    tx.amount > 0 ? 'text-green-400' : 'text-surface-400'
                  }`}
                >
                  {tx.amount > 0 ? '+' : ''}${tx.amount.toFixed(2)}
                </span>
                <span className="text-[10px] font-bold text-surface-500 uppercase tracking-wider w-16 shrink-0">
                  {tx.type}
                </span>
                <span className="text-xs text-surface-400 flex-1 truncate">
                  {tx.description ?? '—'}
                </span>
                <span className="text-[10px] text-surface-600 shrink-0">
                  {new Date(tx.created_at).toLocaleDateString()}
                </span>
                <span className="text-xs font-mono text-surface-500 w-16 text-right shrink-0">
                  ${tx.balance_after.toFixed(2)}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
