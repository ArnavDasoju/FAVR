import { useEffect, useRef, useState } from 'react'

/**
 * MonteCarloViz — demo-grade Monte Carlo simulation visualization.
 *
 * Each "trial" is a random patch-order walk: we step from step-0 (total risk)
 * down to step-N (mostly patched), picking steps in random order. Many trials
 * are drawn as faint sage streamers (spaghetti plot); a bold cream mean curve
 * emerges on top, and per-step end values fall into a histogram along the
 * bottom edge. A live counter shows iterations, mean, and sigma.
 *
 * It uses canvas (not SVG) so thousands of trial lines don't choke the DOM.
 */

type Trial = {
  steps: number[]          // residual risk per step, length = STEPS + 1
  drawProgress: number     // 0..STEPS, how many segments drawn so far
  alpha: number            // fade-in
  hue: number              // small hue variation for visual interest
}

const STEPS = 24                  // patch steps along the X axis
const MAX_LIVE_TRIALS = 40        // how many trials keep drawing at once
const TRIAL_SPAWN_MS = 70         // how often a new trial starts
const DRAW_STEPS_PER_FRAME = 1.2  // how many segments advance each frame
const HISTO_BINS = 24             // bottom distribution bins

function randTrial(): Trial {
  const start = 0.78 + (Math.random() - 0.5) * 0.06
  const end = 0.15 + Math.random() * 0.22
  const steps: number[] = [start]

  // Jittery exponential-ish descent, but each trial takes its own scenic route.
  for (let i = 1; i <= STEPS; i++) {
    const t = i / STEPS
    const baseline = start + (end - start) * (1 - Math.pow(1 - t, 1.6))
    const jitter = (Math.random() - 0.5) * 0.12 * (1 - t * 0.6)
    steps.push(Math.max(0.04, Math.min(0.95, baseline + jitter)))
  }

  return {
    steps,
    drawProgress: 0,
    alpha: 0,
    hue: (Math.random() - 0.5) * 12   // tiny hue jitter
  }
}

export default function MonteCarloViz() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const wrapRef = useRef<HTMLDivElement>(null)
  const rafRef = useRef<number | null>(null)
  const trialsRef = useRef<Trial[]>([])
  const finishedEndsRef = useRef<number[]>([])    // final residual risks, for histogram
  const lastSpawnRef = useRef<number>(0)
  const iterationRef = useRef<number>(0)

  const [stats, setStats] = useState({ iterations: 0, mean: 0, sigma: 0 })

  useEffect(() => {
    const canvas = canvasRef.current
    const wrap = wrapRef.current
    if (!canvas || !wrap) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    // ── HiDPI + resize ─────────────────────────────────────
    const resize = () => {
      const dpr = window.devicePixelRatio || 1
      const w = wrap.clientWidth
      const h = wrap.clientHeight
      canvas.width = w * dpr
      canvas.height = h * dpr
      canvas.style.width = `${w}px`
      canvas.style.height = `${h}px`
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }
    resize()
    const ro = new ResizeObserver(resize)
    ro.observe(wrap)

    // ── Frame loop ─────────────────────────────────────────
    const start = performance.now()
    let statsTick = 0

    const loop = (now: number) => {
      const w = canvas.width / (window.devicePixelRatio || 1)
      const h = canvas.height / (window.devicePixelRatio || 1)

      // Chart area: leave room for histogram strip at the bottom.
      const padL = 36, padR = 14, padT = 14
      const histoH = 32
      const histoGap = 18  // room for label below histogram
      const chartH = h - padT - histoH - histoGap
      const chartW = w - padL - padR
      const xAt = (i: number) => padL + (i / STEPS) * chartW
      const yAt = (v: number) => padT + (1 - v) * chartH

      // Faint trail clear — lets lines linger a moment before fading.
      ctx.fillStyle = 'rgba(248,242,225,0.18)'
      ctx.fillRect(0, 0, w, h)

      // Full-clear pass once in a while so old lines don't ghost forever.
      if (statsTick % 240 === 0) {
        ctx.clearRect(0, 0, w, h)
      }

      // Grid & axes
      ctx.strokeStyle = 'rgba(64,89,53,0.12)'
      ctx.lineWidth = 1
      ctx.beginPath()
      for (let gy = 0; gy <= 4; gy++) {
        const yy = padT + (gy / 4) * chartH
        ctx.moveTo(padL, yy)
        ctx.lineTo(padL + chartW, yy)
      }
      ctx.stroke()

      // Y axis labels
      ctx.fillStyle = 'rgba(74,88,65,0.55)'
      ctx.font = '600 9px Inter, system-ui, sans-serif'
      ctx.textAlign = 'right'
      ctx.textBaseline = 'middle'
      for (let gy = 0; gy <= 4; gy++) {
        const v = 1 - gy / 4
        ctx.fillText(`${Math.round(v * 100)}%`, padL - 6, padT + (gy / 4) * chartH)
      }

      // ── Spawn new trials ─────────────────────────────────
      if (now - lastSpawnRef.current > TRIAL_SPAWN_MS
          && trialsRef.current.filter(t => t.drawProgress < STEPS).length < MAX_LIVE_TRIALS) {
        trialsRef.current.push(randTrial())
        lastSpawnRef.current = now
      }

      // ── Draw trials ──────────────────────────────────────
      const remaining: Trial[] = []
      for (const t of trialsRef.current) {
        // Advance
        t.drawProgress = Math.min(STEPS, t.drawProgress + DRAW_STEPS_PER_FRAME)
        t.alpha = Math.min(1, t.alpha + 0.08)

        const segs = Math.floor(t.drawProgress)
        ctx.lineCap = 'round'
        ctx.lineJoin = 'round'
        ctx.strokeStyle = `rgba(106,143,84,${0.18 * t.alpha})`
        ctx.lineWidth = 1.3
        ctx.beginPath()
        ctx.moveTo(xAt(0), yAt(t.steps[0]))
        for (let i = 1; i <= segs; i++) {
          ctx.lineTo(xAt(i), yAt(t.steps[i]))
        }
        ctx.stroke()

        // Glowing leading dot
        if (segs < STEPS) {
          const headX = xAt(segs)
          const headY = yAt(t.steps[segs])
          const grd = ctx.createRadialGradient(headX, headY, 0, headX, headY, 8)
          grd.addColorStop(0, `rgba(130,169,104,${0.9 * t.alpha})`)
          grd.addColorStop(1, 'rgba(130,169,104,0)')
          ctx.fillStyle = grd
          ctx.beginPath()
          ctx.arc(headX, headY, 8, 0, Math.PI * 2)
          ctx.fill()
        }

        if (t.drawProgress >= STEPS) {
          // Trial complete — feed histogram & retire after a short linger.
          finishedEndsRef.current.push(t.steps[STEPS])
          if (finishedEndsRef.current.length > 800) finishedEndsRef.current.shift()
          iterationRef.current++
          // Keep some lingering trails on screen but don't re-advance.
          if (Math.random() < 0.75) continue
          remaining.push(t)
        } else {
          remaining.push(t)
        }
      }
      trialsRef.current = remaining

      // ── Mean curve (bold) ────────────────────────────────
      if (finishedEndsRef.current.length > 6) {
        // Build a simple "per-step" mean by averaging live trials' step values.
        const perStep = new Array(STEPS + 1).fill(0)
        const counts = new Array(STEPS + 1).fill(0)
        for (const t of trialsRef.current) {
          const upto = Math.floor(t.drawProgress)
          for (let i = 0; i <= upto; i++) {
            perStep[i] += t.steps[i]
            counts[i]++
          }
        }
        ctx.lineWidth = 2.5
        ctx.lineCap = 'round'
        ctx.lineJoin = 'round'
        ctx.strokeStyle = 'rgba(39,48,36,0.92)'
        ctx.beginPath()
        let started = false
        for (let i = 0; i <= STEPS; i++) {
          if (counts[i] === 0) continue
          const v = perStep[i] / counts[i]
          const x = xAt(i), y = yAt(v)
          if (!started) { ctx.moveTo(x, y); started = true } else ctx.lineTo(x, y)
        }
        ctx.stroke()

        // Soft sage outline on top of the mean for polish.
        ctx.lineWidth = 1
        ctx.strokeStyle = 'rgba(130,169,104,0.75)'
        ctx.stroke()
      }

      // ── Histogram (end-state residual-risk distribution) ─
      const ends = finishedEndsRef.current
      if (ends.length > 0) {
        const bins = new Array(HISTO_BINS).fill(0)
        let maxBin = 0
        // Domain for the histo is 0..1 (residual risk).
        for (const v of ends) {
          const i = Math.min(HISTO_BINS - 1, Math.max(0, Math.floor(v * HISTO_BINS)))
          bins[i]++
          if (bins[i] > maxBin) maxBin = bins[i]
        }
        const bw = chartW / HISTO_BINS
        const histTop = padT + chartH + 6  // 6px gap between chart and histo

        // Baseline
        ctx.strokeStyle = 'rgba(64,89,53,0.2)'
        ctx.beginPath()
        ctx.moveTo(padL, histTop + histoH)
        ctx.lineTo(padL + chartW, histTop + histoH)
        ctx.stroke()

        for (let i = 0; i < HISTO_BINS; i++) {
          const c = bins[i]
          if (c === 0) continue
          const bh = (c / maxBin) * histoH
          const x = padL + i * bw
          const y = histTop + (histoH - bh)
          // Sage-gold blend keyed to bin value — lower risk = sager.
          const ratio = i / (HISTO_BINS - 1)
          const r = Math.round(106 + ratio * 78)      // 106 → 184
          const g = Math.round(143 - ratio * 33)      // 143 → 110
          const b = Math.round(84 - ratio * 26)       // 84  → 58
          ctx.fillStyle = `rgba(${r},${g},${b},0.78)`
          ctx.beginPath()
          const radius = Math.min(2.5, bw * 0.4, bh / 2)
          ctx.moveTo(x + 1, histTop + histoH)
          ctx.lineTo(x + 1, y + radius)
          ctx.quadraticCurveTo(x + 1, y, x + 1 + radius, y)
          ctx.lineTo(x + bw - 1 - radius, y)
          ctx.quadraticCurveTo(x + bw - 1, y, x + bw - 1, y + radius)
          ctx.lineTo(x + bw - 1, histTop + histoH)
          ctx.closePath()
          ctx.fill()
        }

        // Mean marker on histogram
        const mean = ends.reduce((s, v) => s + v, 0) / ends.length
        const mx = padL + mean * chartW
        ctx.strokeStyle = 'rgba(39,48,36,0.85)'
        ctx.setLineDash([3, 3])
        ctx.lineWidth = 1.2
        ctx.beginPath()
        ctx.moveTo(mx, histTop)
        ctx.lineTo(mx, histTop + histoH)
        ctx.stroke()
        ctx.setLineDash([])

        // Axis caption — placed below the histogram baseline
        ctx.fillStyle = 'rgba(74,88,65,0.7)'
        ctx.font = '600 8.5px Inter, system-ui, sans-serif'
        ctx.textAlign = 'left'
        ctx.textBaseline = 'top'
        ctx.fillText('RESIDUAL RISK DISTRIBUTION', padL, histTop + histoH + 3)
      }

      // ── Stats refresh (throttled) ───────────────────────
      statsTick++
      if (statsTick % 12 === 0) {
        const ends = finishedEndsRef.current
        if (ends.length > 0) {
          const mean = ends.reduce((s, v) => s + v, 0) / ends.length
          const variance = ends.reduce((s, v) => s + (v - mean) ** 2, 0) / ends.length
          setStats({
            iterations: iterationRef.current,
            mean,
            sigma: Math.sqrt(variance),
          })
        }
      }

      rafRef.current = requestAnimationFrame(loop)
    }

    rafRef.current = requestAnimationFrame(loop)

    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
      ro.disconnect()
    }
  }, [])

  return (
    <div className="glass-card rounded-card overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-sage-500/15">
        <div className="flex items-center gap-2">
          <span className="relative flex w-2 h-2">
            <span className="absolute inline-flex h-full w-full rounded-full bg-sage-500 opacity-60 animate-ping" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-sage-500" />
          </span>
          <h4 className="text-[11px] font-bold tracking-wider text-surface-100 font-display uppercase">
            Monte Carlo · Patch-Order Simulation
          </h4>
        </div>
        <div className="flex items-center gap-3 text-[9.5px] font-mono">
          <Stat label="trials" value={stats.iterations.toLocaleString()} tint="#405935" />
          <Stat label="μ"      value={`${(stats.mean * 100).toFixed(1)}%`} tint="#273024" />
          <Stat label="σ"      value={`${(stats.sigma * 100).toFixed(1)}%`} tint="#8a8d6e" />
        </div>
      </div>

      {/* Canvas */}
      <div ref={wrapRef} className="relative w-full" style={{ height: 220 }}>
        <canvas ref={canvasRef} className="absolute inset-0" />
        {/* Corner wash — parchment depth */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            background:
              'radial-gradient(400px circle at 100% 0%, rgba(130,169,104,0.08), transparent 60%),' +
              'radial-gradient(400px circle at 0% 100%, rgba(184,150,58,0.06), transparent 60%)'
          }}
        />
        {/* Left Y-axis label */}
        <div
          className="absolute left-1 top-1/2 text-[9px] font-bold tracking-widest text-surface-400 uppercase"
          style={{ transform: 'translateY(-50%) rotate(-90deg)', transformOrigin: 'left center' }}
        >
          risk
        </div>
      </div>

      {/* Footer caption */}
      <div className="px-4 py-2 border-t border-sage-500/15 flex items-center justify-between text-[9.5px] text-surface-400">
        <span className="uppercase tracking-widest font-semibold">
          Sampling random patch orders
        </span>
        <span className="font-mono">
          {STEPS} patches &middot; <span className="text-sage-600 font-bold">converging</span>
        </span>
      </div>
    </div>
  )
}

function Stat({ label, value, tint }: { label: string; value: string; tint: string }) {
  return (
    <span className="flex items-baseline gap-1">
      <span className="uppercase tracking-widest text-[8.5px] text-surface-400">{label}</span>
      <span className="font-bold tabular-nums" style={{ color: tint }}>{value}</span>
    </span>
  )
}
