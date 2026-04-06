import { useState, useEffect, useCallback } from 'react'
import { useSettingsStore } from '../stores/settingsStore'
import { useProjectStore } from '../stores/projectStore'

export default function Settings() {
  const settings = useSettingsStore()
  const projects = useProjectStore((s) => s.projects)
  const removeProject = useProjectStore((s) => s.removeProject)

  const [openrouterKey, setOpenrouterKey] = useState(settings.openrouterKey)
  const [geminiKey, setGeminiKey] = useState((settings as any).geminiApiKey ?? '')
  const [confidenceThreshold, setConfidenceThreshold] = useState(settings.confidenceThreshold)
  const [retryLimit, setRetryLimit] = useState(settings.retryLimit)
  const [defaultModel, setDefaultModel] = useState(settings.defaultModel)
  const [ollamaStatus, setOllamaStatus] = useState<'checking' | 'available' | 'unavailable'>('checking')
  const [ollamaModels, setOllamaModels] = useState<string[]>([])
  const [saved, setSaved] = useState(false)

  // Check Ollama on mount
  useEffect(() => {
    checkOllama()
  }, [])

  const checkOllama = async () => {
    setOllamaStatus('checking')
    try {
      const result = await window.api.invoke('ollama:check') as { available: boolean; models: { name: string }[] }
      setOllamaStatus(result.available ? 'available' : 'unavailable')
      setOllamaModels(result.models?.map((m: any) => m.name) ?? [])
    } catch {
      setOllamaStatus('unavailable')
    }
  }

  const handleSave = useCallback(async () => {
    const updates = {
      openrouterKey,
      geminiApiKey: geminiKey,
      confidenceThreshold,
      retryLimit,
      defaultModel
    }

    // Update local store
    settings.updateSettings({
      openrouterKey,
      confidenceThreshold,
      retryLimit,
      defaultModel
    })

    // Push to main process
    try {
      await window.api.invoke('settings:set', updates)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      console.error('Failed to save settings:', err)
    }
  }, [openrouterKey, geminiKey, confidenceThreshold, retryLimit, defaultModel, settings])

  const handleRemoveProject = async (id: string) => {
    removeProject(id)
  }

  const models = [
    { value: 'anthropic/claude-sonnet-4.6', label: 'Claude Sonnet 4.6' },
    { value: 'openai/gpt-5.4', label: 'GPT-5.4' },
    { value: 'deepseek/deepseek-chat', label: 'DeepSeek' },
    { value: 'google/gemini-2.5-flash', label: 'Gemini Flash' },
    { value: 'ollama/llama3', label: 'Ollama Llama3' }
  ]

  return (
    <div className="h-full overflow-y-auto px-6 pb-6">
      <div className="max-w-2xl mx-auto flex flex-col gap-8">

        {/* ── API Keys ──────────────────────────────────────── */}
        <Section title="API Keys">
          <Field label="OpenRouter API Key" description="Required for cloud models (Claude, GPT, DeepSeek). Get one at openrouter.ai">
            <input
              type="password"
              value={openrouterKey}
              onChange={(e) => setOpenrouterKey(e.target.value)}
              placeholder="sk-or-..."
              className="input-field font-mono"
            />
          </Field>

          <Field label="Gemini API Key" description="Optional. Used for free task validation (VLM) and conversation compression. Get one at aistudio.google.com">
            <input
              type="password"
              value={geminiKey}
              onChange={(e) => setGeminiKey(e.target.value)}
              placeholder="AIza..."
              className="input-field font-mono"
            />
          </Field>
        </Section>

        {/* ── Ollama ────────────────────────────────────────── */}
        <Section title="Local Models (Ollama)">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-surface-300">Ollama Status</p>
              <p className="text-xs text-surface-500 mt-0.5">
                Free local models. Install from ollama.com
              </p>
            </div>
            <div className="flex items-center gap-3">
              {ollamaStatus === 'checking' && (
                <span className="text-xs text-surface-500">Checking...</span>
              )}
              {ollamaStatus === 'available' && (
                <span className="text-xs font-bold text-white bg-surface-800 px-3 py-1.5 rounded-btn">
                  Connected
                </span>
              )}
              {ollamaStatus === 'unavailable' && (
                <span className="text-xs text-surface-500 bg-surface-900 px-3 py-1.5 rounded-btn border border-surface-800">
                  Not running
                </span>
              )}
              <button
                onClick={checkOllama}
                className="text-xs font-bold text-surface-400 hover:text-white transition-colors"
              >
                Refresh
              </button>
            </div>
          </div>

          {ollamaModels.length > 0 && (
            <div className="mt-3">
              <p className="text-[10px] font-bold text-surface-500 uppercase tracking-wider mb-2">
                Available Models
              </p>
              <div className="flex flex-wrap gap-2">
                {ollamaModels.map((m) => (
                  <span key={m} className="text-xs font-mono text-surface-300 bg-surface-900 px-2.5 py-1 rounded-btn border border-surface-800">
                    {m}
                  </span>
                ))}
              </div>
            </div>
          )}
        </Section>

        {/* ── Model Preferences ─────────────────────────────── */}
        <Section title="Model Preferences">
          <Field label="Default Model" description="Used when 'Auto' is selected and no preference matches">
            <select
              value={defaultModel}
              onChange={(e) => setDefaultModel(e.target.value)}
              className="input-field"
            >
              {models.map((m) => (
                <option key={m.value} value={m.value}>{m.label}</option>
              ))}
            </select>
          </Field>
        </Section>

        {/* ── Validation ────────────────────────────────────── */}
        <Section title="Validation">
          <Field
            label={`Confidence Threshold — ${confidenceThreshold}%`}
            description="Tasks scoring above this are auto-approved. Below this triggers retry loop or human review."
          >
            <div className="flex items-center gap-4">
              <input
                type="range"
                min={50}
                max={99}
                value={confidenceThreshold}
                onChange={(e) => setConfidenceThreshold(Number(e.target.value))}
                className="flex-1 accent-white"
              />
              <span className="text-sm font-mono text-white w-12 text-right">
                {confidenceThreshold}%
              </span>
            </div>
          </Field>

          <Field
            label={`Retry Limit — ${retryLimit}`}
            description="How many times an agent retries a failed task before asking for human review."
          >
            <div className="flex items-center gap-4">
              <input
                type="range"
                min={0}
                max={5}
                value={retryLimit}
                onChange={(e) => setRetryLimit(Number(e.target.value))}
                className="flex-1 accent-white"
              />
              <span className="text-sm font-mono text-white w-8 text-right">
                {retryLimit}x
              </span>
            </div>
          </Field>
        </Section>

        {/* ── Projects ──────────────────────────────────────── */}
        <Section title="Projects">
          {projects.length === 0 ? (
            <p className="text-sm text-surface-500">
              No projects added. Add one from the Dashboard.
            </p>
          ) : (
            <div className="flex flex-col gap-2">
              {projects.map((p) => (
                <div
                  key={p.id}
                  className="flex items-center justify-between bg-surface-900 border border-surface-800 rounded-btn px-4 py-3"
                >
                  <div>
                    <p className="text-sm font-bold text-white">{p.name}</p>
                    <p className="text-xs font-mono text-surface-500 mt-0.5">{p.directory}</p>
                    {p.devServerUrl && (
                      <p className="text-xs font-mono text-surface-600 mt-0.5">{p.devServerUrl}</p>
                    )}
                  </div>
                  <button
                    onClick={() => handleRemoveProject(p.id)}
                    className="text-xs font-bold text-surface-600 hover:text-white transition-colors"
                  >
                    Remove
                  </button>
                </div>
              ))}
            </div>
          )}
        </Section>

        {/* ── FAVR Engine ─────────────────────────────────── */}
        <Section title="FAVR Engine">
          <Field label="Demo Scenario" description="Load the Meridian Financial Services scenario with 15 real CVEs across 5 services.">
            <button
              onClick={async () => {
                try {
                  await window.api.invoke('analysis:loadDemo')
                } catch (err) {
                  console.error('Demo load failed:', err)
                }
              }}
              className="w-fit bg-surface-800 border border-surface-700 text-white font-bold text-xs py-2 px-4 rounded-btn hover:bg-surface-700 transition-colors"
            >
              Load Demo Scenario
            </button>
          </Field>
        </Section>

        {/* ── Save ──────────────────────────────────────────── */}
        <div className="flex justify-end pb-8">
          <button
            onClick={handleSave}
            className={`px-8 py-3 text-sm font-bold rounded-btn uppercase tracking-wide transition-all ${
              saved
                ? 'bg-surface-800 text-surface-400'
                : 'bg-white text-black hover:bg-surface-200'
            }`}
          >
            {saved ? 'Saved' : 'Save Settings'}
          </button>
        </div>
      </div>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h2 className="text-[10px] font-bold text-surface-500 uppercase tracking-[0.2em] mb-4">
        {title}
      </h2>
      <div className="bg-surface-900 border border-surface-800 rounded-card p-5 flex flex-col gap-5">
        {children}
      </div>
    </div>
  )
}

function Field({ label, description, children }: { label: string; description?: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-2">
      <div>
        <p className="text-sm text-surface-300">{label}</p>
        {description && <p className="text-xs text-surface-600 mt-0.5">{description}</p>}
      </div>
      {children}
    </div>
  )
}
