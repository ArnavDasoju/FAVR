import { useEffect, useRef, useState, useCallback, useMemo } from 'react'
import * as d3 from 'd3'
import { useAnalysisStore } from '../../stores/analysisStore'
import type { FavrService, FavrVulnerability, FavrDependency } from '../../../shared/types'

// Strip scoped-package prefix (@scope/) and convert separators so service labels read cleanly.
// Preserve common acronyms in uppercase; title-case everything else.
const ACRONYMS = new Set([
  'api','url','uri','sql','db','aws','gcp','cdn','ui','ux','cve','iam','http','https',
  'json','xml','yaml','sso','oauth','cli','sdk','npm','vpc','s3','ec2','rds','dns',
  'tcp','udp','tls','ssl','ci','cd','io','jwt','mfa','nfs','smtp','ftp','ssh','rpc',
  'grpc','ml','ai','ip','os','pdf','csv','qr','sms','usb','utf','vm','css','html','js','ts'
])
const cleanName = (raw: string) => {
  const base = raw.replace(/^@[^/]+\//, '').replace(/^@/, '').replace(/[-_/.]+/g, ' ').trim()
  return base.split(/\s+/).filter(Boolean).map(w => {
    const lower = w.toLowerCase()
    if (ACRONYMS.has(lower)) return lower.toUpperCase()
    return lower[0].toUpperCase() + lower.slice(1)
  }).join(' ')
}
const initials = (raw: string) =>
  cleanName(raw).split(' ').filter(Boolean).map(w => w[0]).join('').slice(0, 3).toUpperCase()

// Cream + sage palette. Tier colors tuned for readability on warm cream.
const TIER_COLORS: Record<string, string> = {
  critical: '#B4432E',   // deep brick
  high:     '#C97C2C',   // burnt amber
  medium:   '#B8963A',   // antique gold
  low:      '#6A8F54'    // sage
}

const TIER_GLOW: Record<string, string> = {
  critical: 'rgba(180,67,46,0.35)',
  high:     'rgba(201,124,44,0.32)',
  medium:   'rgba(184,150,58,0.28)',
  low:      'rgba(106,143,84,0.30)'
}

const TIER_LABEL_BG: Record<string, string> = {
  critical: '#FBE4DD',
  high:     '#FBECD9',
  medium:   '#F4EACB',
  low:      '#E1EBD6'
}

const DEP_TYPE_COLORS: Record<string, string> = {
  api:          '#6A8F54',  // sage primary
  data:         '#B8963A',  // antique gold
  auth:         '#C97C2C',  // amber
  'shared-lib': '#8a6fbf'   // dusty violet
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#B4432E',
  high:     '#C97C2C',
  medium:   '#B8963A',
  low:      '#6A8F54',
  info:     '#8a8d6e'
}

interface GraphNode extends d3.SimulationNodeDatum {
  id: string
  name: string
  tier: string
  risk: number
  vulnCount: number
  techStack: string[]
}

interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  type: string
  weight: number
}

export default function DependencyGraph() {
  const result = useAnalysisStore(s => s.result)
  const selectService = useAnalysisStore(s => s.selectService)
  const svgRef = useRef<SVGSVGElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [hoveredNode, setHoveredNode] = useState<string | null>(null)
  const [drilledId, setDrilledId] = useState<string | null>(null)
  const [d3Ready, setD3Ready] = useState(false)
  const simulationRef = useRef<d3.Simulation<GraphNode, GraphLink> | null>(null)

  const toggleFullscreen = useCallback(() => setIsFullscreen(p => !p), [])

  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      if (drilledId) setDrilledId(null)
      else if (isFullscreen) setIsFullscreen(false)
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [isFullscreen, drilledId])

  // Main D3 rendering
  useEffect(() => {
    if (!result || !svgRef.current) return

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()

    const container = svgRef.current.parentElement!
    const width = container.clientWidth
    const height = container.clientHeight
    svg.attr('width', width).attr('height', height)

    const { services, dependencies, vulnerabilities } = result.graph

    const nodes: GraphNode[] = services.map(s => ({
      id: s.id,
      name: s.name,
      tier: s.tier,
      risk: result.riskScores[s.id] ?? 0,
      vulnCount: vulnerabilities.filter(v => v.affectedServiceIds.includes(s.id)).length,
      techStack: s.techStack
    }))

    const links: GraphLink[] = dependencies.map(d => ({
      source: d.from,
      target: d.to,
      type: d.type,
      weight: d.propagationWeight
    }))

    // ────────────────────── Defs ─────────────────
    const defs = svg.append('defs')

    // Parchment background
    const bgGradient = defs.append('radialGradient')
      .attr('id', 'bg-radial')
      .attr('cx', '50%').attr('cy', '40%').attr('r', '80%')
    bgGradient.append('stop').attr('offset', '0%').attr('stop-color', '#fcf8ed').attr('stop-opacity', 1)
    bgGradient.append('stop').attr('offset', '60%').attr('stop-color', '#f5edd4').attr('stop-opacity', 1)
    bgGradient.append('stop').attr('offset', '100%').attr('stop-color', '#ece2bf').attr('stop-opacity', 1)

    svg.append('rect')
      .attr('width', width).attr('height', height)
      .attr('fill', 'url(#bg-radial)')

    // Soft sage fog in upper region
    const sageFog = defs.append('radialGradient')
      .attr('id', 'sage-fog')
      .attr('cx', '50%').attr('cy', '0%').attr('r', '60%')
    sageFog.append('stop').attr('offset', '0%').attr('stop-color', '#82a968').attr('stop-opacity', 0.10)
    sageFog.append('stop').attr('offset', '100%').attr('stop-color', '#82a968').attr('stop-opacity', 0)
    svg.append('rect').attr('width', width).attr('height', height).attr('fill', 'url(#sage-fog)')

    // Dot grid
    const gridPattern = defs.append('pattern')
      .attr('id', 'grid-dots')
      .attr('width', 26).attr('height', 26)
      .attr('patternUnits', 'userSpaceOnUse')
    gridPattern.append('circle')
      .attr('cx', 1).attr('cy', 1).attr('r', 1)
      .attr('fill', '#405935').attr('opacity', 0.08)
    svg.append('rect')
      .attr('width', width).attr('height', height)
      .attr('fill', 'url(#grid-dots)')

    // Vignette
    const vignette = defs.append('radialGradient')
      .attr('id', 'vignette')
      .attr('cx', '50%').attr('cy', '50%').attr('r', '75%')
    vignette.append('stop').attr('offset', '60%').attr('stop-color', '#ece2bf').attr('stop-opacity', 0)
    vignette.append('stop').attr('offset', '100%').attr('stop-color', '#ac9f71').attr('stop-opacity', 0.25)
    svg.append('rect')
      .attr('width', width).attr('height', height)
      .attr('fill', 'url(#vignette)')
      .attr('pointer-events', 'none')

    // Node fills per tier — clean, uniform, slightly darkening toward the edge
    // for a subtle sense of depth without any highlight / gloss.
    Object.entries(TIER_COLORS).forEach(([tier, color]) => {
      const grad = defs.append('radialGradient')
        .attr('id', `node-grad-${tier}`)
        .attr('cx', '50%').attr('cy', '50%').attr('r', '60%')
      grad.append('stop').attr('offset', '0%').attr('stop-color', color).attr('stop-opacity', 1)
      grad.append('stop').attr('offset', '100%').attr('stop-color', color).attr('stop-opacity', 0.88)
    })

    // Glow filter
    const glow = defs.append('filter')
      .attr('id', 'node-glow')
      .attr('x', '-75%').attr('y', '-75%')
      .attr('width', '250%').attr('height', '250%')
    glow.append('feGaussianBlur').attr('stdDeviation', 5).attr('result', 'blur')
    const merge = glow.append('feMerge')
    merge.append('feMergeNode').attr('in', 'blur')
    merge.append('feMergeNode').attr('in', 'SourceGraphic')

    // Link gradients + arrows
    Object.entries(DEP_TYPE_COLORS).forEach(([type, color]) => {
      const lg = defs.append('linearGradient').attr('id', `link-grad-${type}`)
      lg.append('stop').attr('offset', '0%').attr('stop-color', color).attr('stop-opacity', 0.25)
      lg.append('stop').attr('offset', '50%').attr('stop-color', color).attr('stop-opacity', 0.85)
      lg.append('stop').attr('offset', '100%').attr('stop-color', color).attr('stop-opacity', 0.25)

      defs.append('marker')
        .attr('id', `arrow-${type}`)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 34).attr('refY', 0)
        .attr('markerWidth', 7).attr('markerHeight', 7)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-4L8,0L0,4')
        .attr('fill', color).attr('opacity', 0.9)
    })

    // Zoom group
    const zoomGroup = svg.append('g')
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.3, 4])
      .on('zoom', e => zoomGroup.attr('transform', e.transform))
    svg.call(zoom)
    svg.call(zoom.transform, d3.zoomIdentity.translate(width / 2, height / 2).scale(0.9))

    // Background particles — floating sage pollen
    const particles = zoomGroup.append('g').attr('pointer-events', 'none')
    const particleData = d3.range(28).map(() => ({
      x: (Math.random() - 0.5) * width * 1.4,
      y: (Math.random() - 0.5) * height * 1.4,
      r: 0.8 + Math.random() * 1.8,
      phase: Math.random() * Math.PI * 2,
      drift: 0.02 + Math.random() * 0.04
    }))
    const particleSel = particles.selectAll('circle').data(particleData)
      .enter().append('circle')
      .attr('cx', d => d.x).attr('cy', d => d.y)
      .attr('r', d => d.r)
      .attr('fill', '#82a968')
      .attr('opacity', 0.22)

    // Force sim
    const simulation = d3.forceSimulation<GraphNode>(nodes)
      .force('link', d3.forceLink<GraphNode, GraphLink>(links)
        .id(d => d.id)
        .distance(d => 140 + (1 - d.weight) * 80)
        .strength(d => 0.25 + d.weight * 0.5))
      .force('charge', d3.forceManyBody<GraphNode>().strength(d => -420 - d.vulnCount * 60))
      .force('center', d3.forceCenter(0, 0))
      .force('collision', d3.forceCollide<GraphNode>().radius(58))
      .force('x', d3.forceX(0).strength(0.04))
      .force('y', d3.forceY(0).strength(0.04))

    simulationRef.current = simulation

    // Links
    const linkGroup = zoomGroup.append('g')

    const linkBase = linkGroup.selectAll<SVGPathElement, GraphLink>('path.link-base')
      .data(links).enter().append('path')
      .attr('class', 'link-base')
      .attr('fill', 'none')
      .attr('stroke', d => DEP_TYPE_COLORS[d.type] ?? '#8a8d6e')
      .attr('stroke-opacity', 0.2)
      .attr('stroke-width', d => 1.4 + d.weight * 2)
      .attr('stroke-linecap', 'round')

    const linkFlow = linkGroup.selectAll<SVGPathElement, GraphLink>('path.link-flow')
      .data(links).enter().append('path')
      .attr('class', 'link-flow')
      .attr('fill', 'none')
      .attr('stroke', d => `url(#link-grad-${d.type})`)
      .attr('stroke-opacity', 0.9)
      .attr('stroke-width', d => 1.5 + d.weight * 2.5)
      .attr('stroke-linecap', 'round')
      .attr('marker-end', d => `url(#arrow-${d.type})`)

    const linkLabel = zoomGroup.append('g')
      .selectAll<SVGTextElement, GraphLink>('text')
      .data(links).enter().append('text')
      .text(d => d.type)
      .attr('fill', d => DEP_TYPE_COLORS[d.type] ?? '#405935')
      .attr('font-size', 9)
      .attr('font-weight', 600)
      .attr('letter-spacing', 0.4)
      .attr('text-anchor', 'middle')
      .attr('dy', -6)
      .attr('opacity', 0)
      .style('pointer-events', 'none')
      .style('text-transform', 'uppercase')

    // Nodes
    const nodeGroup = zoomGroup.append('g')

    const node = nodeGroup.selectAll<SVGGElement, GraphNode>('g.node')
      .data(nodes).enter().append('g').attr('class', 'node')
      .style('cursor', 'pointer')

    // Critical breathing ring
    node.filter(d => d.tier === 'critical' || d.risk > 0.65)
      .append('circle')
      .attr('r', d => 36 + d.vulnCount * 2.2)
      .attr('fill', 'none')
      .attr('stroke', d => TIER_COLORS[d.tier] ?? '#6a8f54')
      .attr('stroke-width', 1.2)
      .attr('opacity', 0.4)
      .style('transform-origin', 'center')
      .style('animation', 'sagePulse 2.8s ease-in-out infinite')

    // Aura
    node.append('circle')
      .attr('r', d => 32 + d.vulnCount * 2.4)
      .attr('fill', d => TIER_GLOW[d.tier] ?? 'rgba(106,143,84,0.3)')
      .attr('opacity', d => 0.25 + d.risk * 0.5)
      .attr('filter', 'url(#node-glow)')

    // Main orb — flat, clean, thin ring accent for definition
    node.append('circle')
      .attr('r', 26)
      .attr('fill', d => `url(#node-grad-${d.tier})`)
      .attr('stroke', d => TIER_COLORS[d.tier] ?? '#6a8f54')
      .attr('stroke-width', 1)
      .attr('stroke-opacity', 0.55)

    // Initials
    node.append('text')
      .text(d => initials(d.name))
      .attr('fill', '#fcf8ed')
      .attr('font-size', 11)
      .attr('font-weight', 800)
      .attr('text-anchor', 'middle')
      .attr('dy', -1)
      .style('pointer-events', 'none')
      .style('letter-spacing', '0.04em')

    // Risk %
    node.append('text')
      .text(d => `${Math.round(d.risk * 100)}%`)
      .attr('fill', '#fcf8ed')
      .attr('font-size', 8.5)
      .attr('font-weight', 700)
      .attr('text-anchor', 'middle')
      .attr('dy', 11)
      .attr('opacity', 0.9)
      .style('pointer-events', 'none')

    // Name label
    node.append('text')
      .text(d => cleanName(d.name))
      .attr('fill', '#273024')
      .attr('font-size', 11)
      .attr('font-weight', 600)
      .attr('text-anchor', 'middle')
      .attr('dy', 48)
      .attr('opacity', 0.9)
      .style('pointer-events', 'none')
      .style('font-family', "'Fraunces','Inter',serif")

    // Vuln badge
    const vulnBadge = node.filter(d => d.vulnCount > 0).append('g')
    vulnBadge.append('circle')
      .attr('cx', 20).attr('cy', -20).attr('r', 11)
      .attr('fill', d => TIER_COLORS[d.tier] ?? '#6a8f54')
      .attr('stroke', '#fcf8ed').attr('stroke-width', 1.8)
    vulnBadge.append('text')
      .text(d => d.vulnCount)
      .attr('x', 20).attr('y', -16.5)
      .attr('fill', '#fcf8ed')
      .attr('font-size', 10)
      .attr('font-weight', 900)
      .attr('text-anchor', 'middle')
      .style('pointer-events', 'none')

    // "Click for detail" hint ring on hover — adds discoverability of drill-down
    const hintRing = node.append('circle')
      .attr('r', 30).attr('fill', 'none')
      .attr('stroke', '#6a8f54').attr('stroke-width', 1.5)
      .attr('stroke-dasharray', '3 4')
      .attr('opacity', 0)
      .style('pointer-events', 'none')

    // Interactions
    node.on('mouseenter', function (_e, d) {
      setHoveredNode(d.id)
      const connected = new Set<string>([d.id])
      links.forEach(l => {
        const s = typeof l.source === 'object' ? (l.source as GraphNode).id : l.source as string
        const t = typeof l.target === 'object' ? (l.target as GraphNode).id : l.target as string
        if (s === d.id) connected.add(t)
        if (t === d.id) connected.add(s)
      })

      linkFlow.attr('stroke-opacity', l => {
        const s = typeof l.source === 'object' ? (l.source as GraphNode).id : l.source as string
        const t = typeof l.target === 'object' ? (l.target as GraphNode).id : l.target as string
        return (s === d.id || t === d.id) ? 1 : 0.12
      }).attr('stroke-width', l => {
        const s = typeof l.source === 'object' ? (l.source as GraphNode).id : l.source as string
        const t = typeof l.target === 'object' ? (l.target as GraphNode).id : l.target as string
        return (s === d.id || t === d.id) ? 2.8 + l.weight * 3 : 1.4 + l.weight * 2
      })
      linkBase.attr('stroke-opacity', l => {
        const s = typeof l.source === 'object' ? (l.source as GraphNode).id : l.source as string
        const t = typeof l.target === 'object' ? (l.target as GraphNode).id : l.target as string
        return (s === d.id || t === d.id) ? 0.4 : 0.08
      })
      linkLabel.attr('opacity', l => {
        const s = typeof l.source === 'object' ? (l.source as GraphNode).id : l.source as string
        const t = typeof l.target === 'object' ? (l.target as GraphNode).id : l.target as string
        return (s === d.id || t === d.id) ? 0.95 : 0
      })

      node.attr('opacity', n => connected.has(n.id) ? 1 : 0.2)
      d3.select(this).select('circle:last-of-type') // the hintRing is last-appended-at-this-level, but safer to select by class — we re-select below
      d3.select(this).selectAll('circle').filter(function () {
        return d3.select(this).attr('stroke-dasharray') === '3 4'
      }).attr('opacity', 0.85)
      d3.select(this).transition().duration(160)
        .attr('transform', `translate(${d.x},${d.y}) scale(1.18)`)
    })

    node.on('mouseleave', function (_e, d) {
      setHoveredNode(null)
      linkFlow.attr('stroke-opacity', 0.9)
        .attr('stroke-width', l => 1.5 + l.weight * 2.5)
      linkBase.attr('stroke-opacity', 0.2)
      linkLabel.attr('opacity', 0)
      node.attr('opacity', 1)
      d3.select(this).selectAll('circle').filter(function () {
        return d3.select(this).attr('stroke-dasharray') === '3 4'
      }).attr('opacity', 0)
      d3.select(this).transition().duration(160)
        .attr('transform', `translate(${d.x},${d.y}) scale(1)`)
    })

    // Click → drill down
    node.on('click', (_e, d) => {
      selectService(d.id)
      setDrilledId(d.id)
    })

    // Drag
    const drag = d3.drag<SVGGElement, GraphNode>()
      .on('start', (e, d) => {
        if (!e.active) simulation.alphaTarget(0.3).restart()
        d.fx = d.x; d.fy = d.y
      })
      .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y })
      .on('end', (e, d) => {
        if (!e.active) simulation.alphaTarget(0)
        d.fx = null; d.fy = null
      })
    node.call(drag)

    // Curved bezier path
    const curvedPath = (l: GraphLink) => {
      const s = l.source as GraphNode
      const t = l.target as GraphNode
      const sx = s.x ?? 0, sy = s.y ?? 0, tx = t.x ?? 0, ty = t.y ?? 0
      const dx = tx - sx, dy = ty - sy
      const dist = Math.sqrt(dx * dx + dy * dy) || 1
      const hash = ((s.id.charCodeAt(0) + t.id.charCodeAt(0)) % 2 === 0) ? 1 : -1
      const curvature = Math.min(dist * 0.18, 60) * hash
      const mx = (sx + tx) / 2 + (-dy / dist) * curvature
      const my = (sy + ty) / 2 + (dx / dist) * curvature
      return `M${sx},${sy} Q${mx},${my} ${tx},${ty}`
    }

    // Tick
    let tickCount = 0
    simulation.on('tick', () => {
      linkBase.attr('d', curvedPath)
      linkFlow.attr('d', curvedPath)
      linkLabel
        .attr('x', d => (((d.source as GraphNode).x! + (d.target as GraphNode).x!) / 2))
        .attr('y', d => (((d.source as GraphNode).y! + (d.target as GraphNode).y!) / 2))
      node.attr('transform', d => `translate(${d.x},${d.y})`)

      if (tickCount++ % 2 === 0) {
        particleSel.each(function (p: typeof particleData[number]) {
          p.phase += p.drift
          d3.select(this)
            .attr('cx', p.x + Math.sin(p.phase) * 14)
            .attr('cy', p.y + Math.cos(p.phase * 0.7) * 10)
        })
      }

      if (!d3Ready) setD3Ready(true)
    })

    return () => {
      simulation.stop()
      simulationRef.current = null
    }
  }, [result, isFullscreen, selectService])

  // Resize
  useEffect(() => {
    if (!containerRef.current || !svgRef.current) return
    const observer = new ResizeObserver(() => {
      if (simulationRef.current) simulationRef.current.alpha(0.3).restart()
    })
    observer.observe(containerRef.current)
    return () => observer.disconnect()
  }, [])

  if (!result) return null

  const hoveredService = hoveredNode ? result.graph.services.find(s => s.id === hoveredNode) : null
  const hoveredRisk = hoveredNode ? result.riskScores[hoveredNode] : 0

  const drilledService = drilledId ? result.graph.services.find(s => s.id === drilledId) : null
  const drilledRisk = drilledId ? (result.riskScores[drilledId] ?? 0) : 0
  const drilledVulns: FavrVulnerability[] = drilledService
    ? result.graph.vulnerabilities.filter(v => v.affectedServiceIds.includes(drilledService.id))
      .sort((a, b) => (b.cvssScore ?? 0) - (a.cvssScore ?? 0))
    : []
  const drilledDepsOut: FavrDependency[] = drilledService
    ? result.graph.dependencies.filter(d => d.from === drilledService.id)
    : []
  const drilledDepsIn: FavrDependency[] = drilledService
    ? result.graph.dependencies.filter(d => d.to === drilledService.id)
    : []

  const wrapperClasses = isFullscreen
    ? 'fixed inset-0 z-50 flex flex-col bg-surface-950'
    : 'glass-card rounded-card flex flex-col overflow-hidden'

  return (
    <div className={wrapperClasses}>
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3.5 shrink-0 border-b border-sage-500/15 bg-gradient-to-b from-cream-50/60 to-transparent">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-sage-500 shadow-sage-glow animate-pulse-subtle" />
            <h3 className="text-[13px] font-bold tracking-wide text-surface-100 font-display">
              Service Dependency Graph
            </h3>
          </div>
          <p className="text-[10px] text-surface-400 mt-0.5">
            Drag to reposition &middot; scroll to zoom &middot; <span className="text-sage-600 font-semibold">click a node for detail</span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="hidden sm:flex items-center gap-2 mr-2 px-3 py-1.5 rounded-btn bg-cream-50/70 border border-sage-500/20">
            {Object.entries(DEP_TYPE_COLORS).map(([type, color]) => (
              <div key={type} className="flex items-center gap-1.5">
                <span className="w-2.5 h-0.5 rounded-full" style={{ background: color, boxShadow: `0 0 6px ${color}` }} />
                <span className="text-[9px] uppercase tracking-wider text-surface-400 font-semibold">{type}</span>
              </div>
            ))}
          </div>
          <button
            onClick={toggleFullscreen}
            className="p-2 rounded-btn bg-cream-50 border border-sage-500/20 text-surface-300 hover:text-surface-100 hover:border-sage-500/45 hover:bg-cream-100 transition-all btn-hover"
            title={isFullscreen ? 'Exit fullscreen (Esc)' : 'Fullscreen'}
          >
            {isFullscreen ? (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="4 14 10 14 10 20" />
                <polyline points="20 10 14 10 14 4" />
                <line x1="14" y1="10" x2="21" y2="3" />
                <line x1="3" y1="21" x2="10" y2="14" />
              </svg>
            ) : (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="15 3 21 3 21 9" />
                <polyline points="9 21 3 21 3 15" />
                <line x1="21" y1="3" x2="14" y2="10" />
                <line x1="3" y1="21" x2="10" y2="14" />
              </svg>
            )}
          </button>
        </div>
      </div>

      {/* Graph area */}
      <div
        ref={containerRef}
        className="flex-1 relative overflow-hidden"
        style={{ minHeight: isFullscreen ? 0 : 320 }}
      >
        <svg
          ref={svgRef}
          className={`w-full h-full transition-opacity duration-700 ${d3Ready ? 'opacity-100' : 'opacity-0'}`}
        />

        {/* Corner overlays for extra depth */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            background:
              'radial-gradient(600px circle at 100% 0%, rgba(130,169,104,0.10), transparent 50%),' +
              'radial-gradient(500px circle at 0% 100%, rgba(184,150,58,0.08), transparent 55%)'
          }}
        />

        {/* Loading */}
        {!d3Ready && (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="flex flex-col items-center gap-3">
              <div className="relative w-20 h-20">
                {[
                  { x:  0, y: -28, d:   0 },
                  { x: 26, y: -9,  d: 120 },
                  { x: 17, y: 22,  d: 240 },
                  { x: -17, y: 22, d: 360 },
                  { x: -26, y: -9, d: 480 },
                ].map((pos, i) => (
                  <div
                    key={i}
                    className="absolute rounded-full"
                    style={{
                      width: 18, height: 18,
                      left: `calc(50% + ${pos.x}px - 9px)`,
                      top:  `calc(50% + ${pos.y}px - 9px)`,
                      background: 'radial-gradient(circle, rgba(130,169,104,0.9), rgba(64,89,53,0.2))',
                      animation: 'pulse-subtle 1.6s ease-in-out infinite',
                      animationDelay: `${pos.d}ms`,
                    }}
                  />
                ))}
              </div>
              <span className="text-[10px] text-surface-400 uppercase tracking-widest font-semibold">
                Weaving attack graph
              </span>
            </div>
          </div>
        )}

        {/* Hover tooltip (hidden when drilled) */}
        {hoveredService && !drilledId && (
          <div className="absolute top-4 right-4 glass-card rounded-card p-3.5 pointer-events-none max-w-[240px] animate-fadeIn">
            <div className="flex items-center gap-2 mb-2">
              <span
                className="w-2 h-2 rounded-full shrink-0"
                style={{ background: TIER_COLORS[hoveredService.tier], boxShadow: `0 0 10px ${TIER_COLORS[hoveredService.tier]}` }}
              />
              <div className="text-[13px] font-bold text-surface-100 font-display leading-tight">
                {cleanName(hoveredService.name)}
              </div>
            </div>
            <div className="flex items-center gap-2 mb-2">
              <span
                className="text-[9px] font-bold uppercase px-2 py-0.5 rounded tracking-wider"
                style={{
                  color: TIER_COLORS[hoveredService.tier],
                  background: TIER_LABEL_BG[hoveredService.tier],
                  border: `1px solid ${TIER_COLORS[hoveredService.tier]}40`
                }}
              >
                {hoveredService.tier}
              </span>
              <span className="text-[10px] text-surface-300 font-mono">
                risk <span className="text-surface-100 font-bold">{Math.round(hoveredRisk * 100)}%</span>
              </span>
            </div>
            <div className="text-[10px] text-surface-300 mb-2 leading-snug">
              {hoveredService.description}
            </div>
            {hoveredService.techStack.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-2">
                {hoveredService.techStack.map(t => (
                  <span key={t} className="sage-chip text-[9px] px-1.5 py-0.5 rounded font-medium">{t}</span>
                ))}
              </div>
            )}
            <div className="text-[9px] text-sage-600 font-bold uppercase tracking-widest pt-1 border-t border-sage-500/20">
              Click to open detail →
            </div>
          </div>
        )}

        {/* Fullscreen HUD */}
        {isFullscreen && !drilledId && (
          <div className="absolute bottom-5 left-5 flex items-center gap-3 px-3.5 py-2 rounded-btn glass-card text-[10px] text-surface-300 uppercase tracking-wider">
            <span>scroll · zoom</span>
            <span className="text-sage-500">/</span>
            <span>drag bg · pan</span>
            <span className="text-sage-500">/</span>
            <span>click node · detail</span>
            <span className="text-sage-500">/</span>
            <span>esc · exit</span>
          </div>
        )}

        {/* ───────── Drill-down panel ───────── */}
        {drilledService && (
          <DrillDownPanel
            service={drilledService}
            risk={drilledRisk}
            vulns={drilledVulns}
            depsOut={drilledDepsOut}
            depsIn={drilledDepsIn}
            allServices={result.graph.services}
            onBack={() => setDrilledId(null)}
          />
        )}
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────
// DRILL-DOWN PANEL — service detail with vulns, deps, priority patches
// ─────────────────────────────────────────────────────────────────

function DrillDownPanel({
  service, risk, vulns, depsOut, depsIn, allServices, onBack,
}: {
  service: FavrService
  risk: number
  vulns: FavrVulnerability[]
  depsOut: FavrDependency[]
  depsIn: FavrDependency[]
  allServices: FavrService[]
  onBack: () => void
}) {
  const [tab, setTab] = useState<'vulns' | 'deps' | 'tasks'>('vulns')
  const nameOf = useMemo(() => {
    const m = new Map<string, string>()
    allServices.forEach(s => m.set(s.id, cleanName(s.name)))
    return m
  }, [allServices])

  const tierColor = TIER_COLORS[service.tier] ?? '#6a8f54'
  const criticalCount = vulns.filter(v => v.severity === 'critical').length
  const kevCount = vulns.filter(v => v.inKev).length

  const patchQueue = [...vulns]
    .filter(v => v.status === 'open' || v.status === 'in-progress')
    .sort((a, b) => {
      if (a.patchOrder != null && b.patchOrder != null) return a.patchOrder - b.patchOrder
      return (b.cvssScore ?? 0) - (a.cvssScore ?? 0)
    })

  return (
    <div className="absolute inset-0 flex animate-fadeIn">
      {/* Dim backdrop over graph */}
      <button
        onClick={onBack}
        aria-label="Close detail"
        className="absolute inset-0 bg-cream-50/75 backdrop-blur-sm"
        style={{ cursor: 'zoom-out' }}
      />

      {/* Main detail card — fills most of the graph area */}
      <div className="relative m-4 flex-1 animate-slideInRight glass-card rounded-card overflow-hidden flex flex-col">
        {/* Hero stripe tinted by tier */}
        <div
          className="h-1.5 w-full shrink-0"
          style={{ background: `linear-gradient(90deg, ${tierColor} 0%, ${tierColor}55 100%)` }}
        />

        {/* Header */}
        <div className="px-5 pt-4 pb-3 flex items-start justify-between gap-4">
          <div className="flex items-start gap-3 min-w-0">
            <div
              className="w-14 h-14 rounded-2xl shrink-0 flex items-center justify-center relative overflow-hidden"
              style={{
                background: `linear-gradient(135deg, ${tierColor} 0%, ${tierColor}AA 100%)`,
                boxShadow: `0 10px 26px -10px ${tierColor}88, inset 0 1px 0 rgba(255,255,255,0.45)`,
              }}
            >
              <span className="text-lg font-black text-white tracking-tight relative z-10" style={{ textShadow: '0 1px 3px rgba(0,0,0,0.25)' }}>
                {initials(service.name)}
              </span>
              <span className="absolute inset-0 bg-gradient-to-br from-white/25 to-transparent" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                <span
                  className="text-[10px] font-bold uppercase px-2 py-0.5 rounded tracking-wider"
                  style={{
                    color: tierColor,
                    background: TIER_LABEL_BG[service.tier],
                    border: `1px solid ${tierColor}40`,
                  }}
                >
                  {service.tier} tier
                </span>
                <span className="text-[10px] text-surface-400 font-mono">#{service.id}</span>
                {kevCount > 0 && (
                  <span className="text-[9px] font-bold uppercase px-2 py-0.5 rounded tracking-wider bg-[#B4432E]/10 text-[#B4432E] border border-[#B4432E]/40">
                    {kevCount} in CISA KEV
                  </span>
                )}
              </div>
              <h2 className="text-xl font-black font-display text-surface-100 leading-tight truncate">
                {cleanName(service.name)}
              </h2>
              <p className="text-[11px] text-surface-400 mt-1 max-w-xl leading-snug">
                {service.description}
              </p>
            </div>
          </div>

          <button
            onClick={onBack}
            className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-btn text-[11px] font-semibold text-surface-300 hover:text-surface-100 bg-cream-50 hover:bg-cream-100 border border-sage-500/20 hover:border-sage-500/50 transition-all btn-hover"
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="15 18 9 12 15 6" />
            </svg>
            Back to graph
          </button>
        </div>

        {/* Stat row */}
        <div className="px-5 pb-3 grid grid-cols-3 gap-2.5">
          <StatTile
            label="Propagated risk"
            value={`${Math.round(risk * 100)}%`}
            tint={risk > 0.7 ? '#B4432E' : risk > 0.4 ? '#C97C2C' : '#6A8F54'}
          />
          <StatTile label="Vulnerabilities" value={String(vulns.length)} tint="#B4432E" muted={vulns.length === 0} />
          <StatTile label="Critical" value={String(criticalCount)} tint="#B4432E" muted={criticalCount === 0} />
        </div>

        {/* Tech stack chips */}
        {service.techStack.length > 0 && (
          <div className="px-5 pb-2 flex flex-wrap gap-1.5">
            {service.techStack.map(t => (
              <span key={t} className="sage-chip text-[10px] px-2 py-1 rounded-btn font-semibold">
                {t}
              </span>
            ))}
            {service.complianceFrameworks.map(cf => (
              <span
                key={cf}
                className="text-[10px] px-2 py-1 rounded-btn font-bold uppercase tracking-wider"
                style={{ background: '#F4EACB', color: '#8a6a1a', border: '1px solid #d4b97a' }}
              >
                {cf}
              </span>
            ))}
          </div>
        )}

        {/* Tabs */}
        <div className="px-5 pt-2 border-b border-sage-500/15 flex gap-1">
          {([
            { id: 'vulns', label: `Vulnerabilities`, count: vulns.length },
            { id: 'deps',  label: `Dependencies`,    count: depsIn.length + depsOut.length },
            { id: 'tasks', label: `Priority Tasks`,  count: patchQueue.length },
          ] as const).map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`relative px-3.5 py-2 text-[11px] font-semibold transition-colors ${
                tab === t.id ? 'text-sage-700' : 'text-surface-400 hover:text-surface-200'
              }`}
            >
              {t.label}
              <span className={`ml-1.5 text-[9px] font-mono px-1.5 py-0.5 rounded ${
                tab === t.id ? 'bg-sage-500/15 text-sage-700' : 'bg-cream-300 text-surface-400'
              }`}>
                {t.count}
              </span>
              {tab === t.id && (
                <span
                  className="absolute bottom-[-1px] left-0 right-0 h-[2px] rounded-t-full animate-scaleIn"
                  style={{ background: 'linear-gradient(90deg,#82a968,#405935)' }}
                />
              )}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div className="flex-1 overflow-auto px-5 py-4">
          {tab === 'vulns' && (
            <div className="flex flex-col gap-2">
              {vulns.length === 0 && <EmptyNote text="No vulnerabilities in this service." />}
              {vulns.map((v, i) => <VulnCard key={v.id} v={v} index={i} />)}
            </div>
          )}
          {tab === 'deps' && (
            <div className="grid grid-cols-2 gap-4">
              <DepColumn title="Incoming" deps={depsIn} nameOf={nameOf} direction="in" />
              <DepColumn title="Outgoing" deps={depsOut} nameOf={nameOf} direction="out" />
            </div>
          )}
          {tab === 'tasks' && (
            <div className="flex flex-col gap-2">
              {patchQueue.length === 0 && <EmptyNote text="Everything patched — nothing to schedule." />}
              {patchQueue.map((v, i) => (
                <TaskCard key={v.id} v={v} position={i + 1} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── small helpers ─────────────────────────────────────────────

function StatTile({ label, value, tint, muted }: { label: string; value: string; tint: string; muted?: boolean }) {
  return (
    <div
      className="relative rounded-card p-3 border overflow-hidden"
      style={{
        background: muted ? '#F2EAD3' : `linear-gradient(135deg, ${tint}12, ${tint}04)`,
        borderColor: muted ? '#d9cba6' : `${tint}38`,
      }}
    >
      <div className="text-[9px] uppercase font-bold tracking-widest" style={{ color: muted ? '#8a8d6e' : tint, opacity: muted ? 0.9 : 1 }}>
        {label}
      </div>
      <div
        className="font-display font-black text-2xl leading-none mt-1"
        style={{ color: muted ? '#8a8d6e' : tint }}
      >
        {value}
      </div>
    </div>
  )
}

function EmptyNote({ text }: { text: string }) {
  return (
    <div className="text-center py-10 text-[12px] text-surface-400 italic font-display">
      {text}
    </div>
  )
}

function VulnCard({ v, index }: { v: FavrVulnerability; index: number }) {
  const sevColor = SEVERITY_COLORS[v.severity] ?? '#8a8d6e'
  return (
    <div
      className="group rounded-card p-3.5 border bg-cream-50/80 hover:bg-cream-50 card-hover animate-slideUp"
      style={{ borderColor: `${sevColor}35`, animationDelay: `${index * 40}ms` }}
    >
      <div className="flex items-start gap-3">
        {/* severity dot */}
        <div className="relative shrink-0 mt-0.5">
          <div
            className="w-2.5 h-2.5 rounded-full"
            style={{ background: sevColor, boxShadow: `0 0 10px ${sevColor}` }}
          />
          {v.inKev && (
            <div
              className="absolute -inset-1 rounded-full border animate-pulse-subtle"
              style={{ borderColor: sevColor }}
            />
          )}
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span
              className="text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
              style={{ color: sevColor, background: `${sevColor}12`, border: `1px solid ${sevColor}44` }}
            >
              {v.severity}
            </span>
            <span className="text-[11px] font-mono font-bold text-surface-200">{v.cveId}</span>
            {v.knownExploit && (
              <span className="text-[9px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wider bg-[#B4432E]/10 text-[#B4432E] border border-[#B4432E]/35">
                exploited in wild
              </span>
            )}
            {v.hasPublicExploit && !v.knownExploit && (
              <span className="text-[9px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wider bg-[#C97C2C]/10 text-[#C97C2C] border border-[#C97C2C]/35">
                public PoC
              </span>
            )}
          </div>
          <div className="text-[12px] font-semibold text-surface-100 leading-snug mb-1">{v.title}</div>
          <div className="text-[10.5px] text-surface-400 leading-snug mb-2 line-clamp-2">{v.description}</div>

          <div className="flex items-center gap-3 flex-wrap text-[10px]">
            <MetricBadge label="CVSS"   value={v.cvssScore.toFixed(1)} emphasis={v.cvssScore >= 7} />
            <MetricBadge label="EPSS"   value={`${(v.epssScore * 100).toFixed(1)}%`} emphasis={v.epssScore > 0.1} />
            <MetricBadge label="Exploit" value={`${Math.round(v.exploitProbability * 100)}%`} />
            <span className="text-surface-400 font-mono">
              <span className="text-surface-500">pkg</span> <span className="text-surface-200">{v.affectedPackage}</span>
            </span>
            {v.patchedVersion && (
              <span className="text-surface-400 font-mono">
                <span className="text-surface-500">→</span>{' '}
                <span className="text-sage-700 font-bold">v{v.patchedVersion}</span>
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function MetricBadge({ label, value, emphasis }: { label: string; value: string; emphasis?: boolean }) {
  return (
    <span
      className="inline-flex items-center gap-1 font-mono px-1.5 py-0.5 rounded"
      style={{
        background: emphasis ? 'rgba(180,67,46,0.08)' : 'rgba(106,143,84,0.08)',
        border: `1px solid ${emphasis ? 'rgba(180,67,46,0.28)' : 'rgba(106,143,84,0.25)'}`,
      }}
    >
      <span className="text-[8.5px] uppercase tracking-wider" style={{ color: emphasis ? '#B4432E' : '#527141' }}>
        {label}
      </span>
      <span className={`font-bold ${emphasis ? 'text-[#B4432E]' : 'text-surface-200'}`}>{value}</span>
    </span>
  )
}

function DepColumn({
  title, deps, nameOf, direction,
}: {
  title: string
  deps: FavrDependency[]
  nameOf: Map<string, string>
  direction: 'in' | 'out'
}) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2 text-[10px] uppercase font-bold tracking-widest text-surface-400">
        <span className="w-1 h-1 rounded-full bg-sage-500" />
        {title} <span className="font-mono text-surface-500">· {deps.length}</span>
      </div>
      {deps.length === 0 && <div className="text-[11px] text-surface-400 italic">None</div>}
      {deps.map((d, i) => {
        const otherId = direction === 'in' ? d.from : d.to
        const color = DEP_TYPE_COLORS[d.type] ?? '#6a8f54'
        return (
          <div
            key={`${d.from}-${d.to}-${i}`}
            className="rounded-card p-2.5 border bg-cream-50/80 card-hover animate-slideUp"
            style={{ borderColor: `${color}35`, animationDelay: `${i * 40}ms` }}
          >
            <div className="flex items-center gap-2 mb-1">
              <span
                className="text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
                style={{ color, background: `${color}15`, border: `1px solid ${color}45` }}
              >
                {d.type}
              </span>
              <span className="text-[10px] font-mono text-surface-400">
                weight {d.propagationWeight.toFixed(2)}
              </span>
            </div>
            <div className="text-[11.5px] font-semibold text-surface-100">
              {nameOf.get(otherId) ?? otherId}
            </div>
            {d.description && (
              <div className="text-[10px] text-surface-400 mt-0.5 leading-snug">{d.description}</div>
            )}
          </div>
        )
      })}
    </div>
  )
}

function TaskCard({ v, position }: { v: FavrVulnerability; position: number }) {
  const sevColor = SEVERITY_COLORS[v.severity] ?? '#8a8d6e'
  return (
    <div
      className="group rounded-card p-3.5 border bg-cream-50/80 hover:bg-cream-50 card-hover animate-slideUp flex items-start gap-3"
      style={{ borderColor: `${sevColor}30`, animationDelay: `${position * 40}ms` }}
    >
      <div
        className="shrink-0 w-8 h-8 rounded-btn flex items-center justify-center font-display font-black text-sm"
        style={{
          background: `linear-gradient(135deg, ${sevColor}, ${sevColor}AA)`,
          color: '#fcf8ed',
          boxShadow: `0 4px 12px -4px ${sevColor}66`,
        }}
      >
        {position}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 mb-1 flex-wrap">
          <span className="text-[11px] font-mono font-bold text-surface-200">{v.cveId}</span>
          <span
            className="text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
            style={{ color: sevColor, background: `${sevColor}15`, border: `1px solid ${sevColor}40` }}
          >
            {v.complexity} effort
          </span>
        </div>
        <div className="text-[12px] font-semibold text-surface-100 leading-snug mb-1">{v.title}</div>
        <div className="flex items-center gap-3 text-[10px] text-surface-400 flex-wrap">
          <span>
            <span className="text-surface-500">cost</span>{' '}
            <span className="text-surface-200 font-mono">{v.remediationCost}h</span>
          </span>
          <span>
            <span className="text-surface-500">downtime</span>{' '}
            <span className="text-surface-200 font-mono">{v.remediationDowntime}m</span>
          </span>
          <span>
            <span className="text-surface-500">upgrade</span>{' '}
            <span className="text-sage-700 font-mono font-bold">{v.affectedPackage}@{v.patchedVersion}</span>
          </span>
        </div>
      </div>
    </div>
  )
}
