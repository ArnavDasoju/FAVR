import { useEffect, useRef, useState, useCallback } from 'react'
import * as d3 from 'd3'
import { useAnalysisStore } from '../../stores/analysisStore'

const TIER_COLORS: Record<string, string> = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#EAB308',
  low: '#3B82F6'
}

const DEP_TYPE_COLORS: Record<string, string> = {
  api: '#6366F1',
  data: '#22C55E',
  auth: '#F59E0B',
  'shared-lib': '#EC4899'
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
  const simulationRef = useRef<d3.Simulation<GraphNode, GraphLink> | null>(null)

  const toggleFullscreen = useCallback(() => {
    setIsFullscreen(prev => !prev)
  }, [])

  // Handle Escape key to exit fullscreen
  useEffect(() => {
    if (!isFullscreen) return
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setIsFullscreen(false)
    }
    window.addEventListener('keydown', handleKey)
    return () => window.removeEventListener('keydown', handleKey)
  }, [isFullscreen])

  // Main D3 rendering
  useEffect(() => {
    if (!result || !svgRef.current) return

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()

    const container = svgRef.current.parentElement!
    const width = container.clientWidth
    const height = container.clientHeight

    svg.attr('width', width).attr('height', height)

    // Build graph data
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

    // Zoom behavior
    const zoomGroup = svg.append('g')

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.3, 4])
      .on('zoom', (event) => {
        zoomGroup.attr('transform', event.transform)
      })

    svg.call(zoom)

    // Initial centering
    const initialTransform = d3.zoomIdentity
      .translate(width / 2, height / 2)
      .scale(0.9)
    svg.call(zoom.transform, initialTransform)

    // Arrow markers for each dependency type
    const defs = zoomGroup.append('defs')

    Object.entries(DEP_TYPE_COLORS).forEach(([type, color]) => {
      defs.append('marker')
        .attr('id', `arrow-${type}`)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 30)
        .attr('refY', 0)
        .attr('markerWidth', 8)
        .attr('markerHeight', 8)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-4L8,0L0,4')
        .attr('fill', color)
        .attr('opacity', 0.7)
    })

    // Glow filter
    const filter = defs.append('filter')
      .attr('id', 'node-glow')
      .attr('x', '-50%').attr('y', '-50%')
      .attr('width', '200%').attr('height', '200%')
    filter.append('feGaussianBlur')
      .attr('stdDeviation', '4')
      .attr('result', 'blur')
    filter.append('feMerge')
      .selectAll('feMergeNode')
      .data(['blur', 'SourceGraphic'])
      .enter()
      .append('feMergeNode')
      .attr('in', d => d)

    // Force simulation
    const simulation = d3.forceSimulation<GraphNode>(nodes)
      .force('link', d3.forceLink<GraphNode, GraphLink>(links)
        .id(d => d.id)
        .distance(d => 120 + (1 - d.weight) * 60)
        .strength(d => 0.3 + d.weight * 0.5)
      )
      .force('charge', d3.forceManyBody<GraphNode>()
        .strength(d => -300 - d.vulnCount * 50)
      )
      .force('center', d3.forceCenter(0, 0))
      .force('collision', d3.forceCollide<GraphNode>().radius(50))
      .force('x', d3.forceX(0).strength(0.05))
      .force('y', d3.forceY(0).strength(0.05))

    simulationRef.current = simulation

    // Links
    const linkGroup = zoomGroup.append('g').attr('class', 'links')

    const link = linkGroup.selectAll<SVGLineElement, GraphLink>('line')
      .data(links)
      .enter()
      .append('line')
      .attr('stroke', d => DEP_TYPE_COLORS[d.type] ?? '#3F3F46')
      .attr('stroke-width', d => 1 + d.weight * 2.5)
      .attr('stroke-opacity', 0.4)
      .attr('marker-end', d => `url(#arrow-${d.type})`)

    // Link labels
    const linkLabel = zoomGroup.append('g').attr('class', 'link-labels')
      .selectAll<SVGTextElement, GraphLink>('text')
      .data(links)
      .enter()
      .append('text')
      .text(d => d.type)
      .attr('fill', d => DEP_TYPE_COLORS[d.type] ?? '#52525B')
      .attr('font-size', '9')
      .attr('text-anchor', 'middle')
      .attr('dy', -6)
      .attr('opacity', 0.5)
      .style('pointer-events', 'none')

    // Node groups
    const nodeGroup = zoomGroup.append('g').attr('class', 'nodes')

    const node = nodeGroup.selectAll<SVGGElement, GraphNode>('g')
      .data(nodes)
      .enter()
      .append('g')
      .style('cursor', 'grab')

    // Outer glow ring (risk-based)
    node.append('circle')
      .attr('r', d => 28 + d.vulnCount * 3)
      .attr('fill', d => TIER_COLORS[d.tier] ?? '#666')
      .attr('opacity', d => 0.08 + d.risk * 0.12)
      .attr('filter', 'url(#node-glow)')

    // Main circle
    node.append('circle')
      .attr('r', 24)
      .attr('fill', '#18181B')
      .attr('stroke', d => TIER_COLORS[d.tier] ?? '#666')
      .attr('stroke-width', 2.5)

    // Inner risk fill
    node.append('circle')
      .attr('r', 20)
      .attr('fill', d => TIER_COLORS[d.tier] ?? '#666')
      .attr('opacity', d => d.risk * 0.4)

    // Initials label
    node.append('text')
      .text(d => d.name.split(' ').map(w => w[0]).join('').toUpperCase())
      .attr('fill', 'white')
      .attr('font-size', '10')
      .attr('font-weight', 'bold')
      .attr('text-anchor', 'middle')
      .attr('dy', -2)
      .style('pointer-events', 'none')

    // Risk percentage
    node.append('text')
      .text(d => `${Math.round(d.risk * 100)}%`)
      .attr('fill', '#A1A1AA')
      .attr('font-size', '8')
      .attr('text-anchor', 'middle')
      .attr('dy', 10)
      .style('pointer-events', 'none')

    // Name below node
    node.append('text')
      .text(d => d.name)
      .attr('fill', '#71717A')
      .attr('font-size', '10')
      .attr('text-anchor', 'middle')
      .attr('dy', 42)
      .style('pointer-events', 'none')

    // Vuln count badge
    node.filter(d => d.vulnCount > 0)
      .append('circle')
      .attr('cx', 18)
      .attr('cy', -18)
      .attr('r', 10)
      .attr('fill', '#18181B')
      .attr('stroke', d => TIER_COLORS[d.tier] ?? '#666')
      .attr('stroke-width', 1.5)

    node.filter(d => d.vulnCount > 0)
      .append('text')
      .text(d => d.vulnCount)
      .attr('x', 18)
      .attr('y', -14)
      .attr('fill', d => TIER_COLORS[d.tier] ?? '#666')
      .attr('font-size', '9')
      .attr('font-weight', 'bold')
      .attr('text-anchor', 'middle')
      .style('pointer-events', 'none')

    // Hover interactions
    node.on('mouseenter', function (_event, d) {
      setHoveredNode(d.id)

      // Highlight connected links
      link.attr('stroke-opacity', l => {
        const src = typeof l.source === 'object' ? (l.source as GraphNode).id : l.source
        const tgt = typeof l.target === 'object' ? (l.target as GraphNode).id : l.target
        return src === d.id || tgt === d.id ? 0.9 : 0.1
      }).attr('stroke-width', l => {
        const src = typeof l.source === 'object' ? (l.source as GraphNode).id : l.source
        const tgt = typeof l.target === 'object' ? (l.target as GraphNode).id : l.target
        return src === d.id || tgt === d.id ? 2 + l.weight * 3 : 1 + l.weight * 2
      })

      linkLabel.attr('opacity', l => {
        const src = typeof l.source === 'object' ? (l.source as GraphNode).id : l.source
        const tgt = typeof l.target === 'object' ? (l.target as GraphNode).id : l.target
        return src === d.id || tgt === d.id ? 0.9 : 0
      })

      // Dim non-connected nodes
      const connectedIds = new Set<string>([d.id])
      links.forEach(l => {
        const src = typeof l.source === 'object' ? (l.source as GraphNode).id : l.source as string
        const tgt = typeof l.target === 'object' ? (l.target as GraphNode).id : l.target as string
        if (src === d.id) connectedIds.add(tgt)
        if (tgt === d.id) connectedIds.add(src)
      })

      node.attr('opacity', n => connectedIds.has(n.id) ? 1 : 0.2)

      // Scale up hovered node
      d3.select(this)
        .transition().duration(150)
        .attr('transform', `translate(${d.x},${d.y}) scale(1.15)`)
    })

    node.on('mouseleave', function (_event, d) {
      setHoveredNode(null)
      link.attr('stroke-opacity', 0.4)
        .attr('stroke-width', l => 1 + l.weight * 2.5)
      linkLabel.attr('opacity', 0.5)
      node.attr('opacity', 1)

      d3.select(this)
        .transition().duration(150)
        .attr('transform', `translate(${d.x},${d.y}) scale(1)`)
    })

    // Click to select service
    node.on('click', (_event, d) => {
      selectService(d.id)
    })

    // Drag behavior
    const drag = d3.drag<SVGGElement, GraphNode>()
      .on('start', (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart()
        d.fx = d.x
        d.fy = d.y
        d3.select(event.sourceEvent.target.closest('g')).style('cursor', 'grabbing')
      })
      .on('drag', (event, d) => {
        d.fx = event.x
        d.fy = event.y
      })
      .on('end', (event, d) => {
        if (!event.active) simulation.alphaTarget(0)
        d.fx = null
        d.fy = null
        d3.select(event.sourceEvent.target.closest('g')).style('cursor', 'grab')
      })

    node.call(drag)

    // Tick function
    simulation.on('tick', () => {
      link
        .attr('x1', d => (d.source as GraphNode).x!)
        .attr('y1', d => (d.source as GraphNode).y!)
        .attr('x2', d => (d.target as GraphNode).x!)
        .attr('y2', d => (d.target as GraphNode).y!)

      linkLabel
        .attr('x', d => ((d.source as GraphNode).x! + (d.target as GraphNode).x!) / 2)
        .attr('y', d => ((d.source as GraphNode).y! + (d.target as GraphNode).y!) / 2)

      node.attr('transform', d => `translate(${d.x},${d.y})`)
    })

    // Cleanup
    return () => {
      simulation.stop()
      simulationRef.current = null
    }
  }, [result, isFullscreen, selectService])

  // Resize observer
  useEffect(() => {
    if (!containerRef.current || !svgRef.current) return
    const observer = new ResizeObserver(() => {
      // Re-trigger by toggling a transient state (the full effect re-runs on isFullscreen change)
      if (simulationRef.current) {
        simulationRef.current.alpha(0.3).restart()
      }
    })
    observer.observe(containerRef.current)
    return () => observer.disconnect()
  }, [])

  if (!result) return null

  // Get hovered node details for the tooltip
  const hoveredService = hoveredNode
    ? result.graph.services.find(s => s.id === hoveredNode)
    : null
  const hoveredRisk = hoveredNode ? result.riskScores[hoveredNode] : 0

  const wrapperClasses = isFullscreen
    ? 'fixed inset-0 z-50 bg-surface-950 flex flex-col'
    : 'bg-surface-900 border border-surface-800 rounded-card flex flex-col'

  return (
    <div className={wrapperClasses}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 shrink-0">
        <div>
          <h3 className="text-sm font-bold text-white">Service Dependency Graph</h3>
          <p className="text-[10px] text-surface-500">
            Drag nodes to reposition &middot; Scroll to zoom &middot; Click node to inspect
          </p>
        </div>
        <div className="flex items-center gap-2">
          {/* Legend */}
          <div className="hidden sm:flex items-center gap-3 mr-3">
            {Object.entries(DEP_TYPE_COLORS).map(([type, color]) => (
              <div key={type} className="flex items-center gap-1">
                <span className="w-3 h-0.5 rounded-full" style={{ background: color }} />
                <span className="text-[9px] text-surface-500">{type}</span>
              </div>
            ))}
          </div>
          <button
            onClick={toggleFullscreen}
            className="p-1.5 rounded-btn bg-surface-800 hover:bg-surface-700 text-surface-400 hover:text-white transition-colors"
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
        style={{ minHeight: isFullscreen ? 0 : 280 }}
      >
        <svg
          ref={svgRef}
          className="w-full h-full"
          style={{ background: isFullscreen ? '#09090B' : 'transparent' }}
        />

        {/* Hover tooltip */}
        {hoveredService && (
          <div className="absolute top-3 right-3 bg-surface-900/95 border border-surface-700 rounded-card p-3 shadow-lg backdrop-blur-sm pointer-events-none max-w-[200px]">
            <div className="text-xs font-bold text-white mb-1">{hoveredService.name}</div>
            <div className="flex items-center gap-2 mb-2">
              <span
                className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
                style={{
                  color: TIER_COLORS[hoveredService.tier],
                  background: `${TIER_COLORS[hoveredService.tier]}15`,
                  border: `1px solid ${TIER_COLORS[hoveredService.tier]}30`
                }}
              >
                {hoveredService.tier}
              </span>
              <span className="text-[10px] text-surface-400 font-mono">
                Risk {Math.round(hoveredRisk * 100)}%
              </span>
            </div>
            <div className="text-[10px] text-surface-500 mb-1.5">{hoveredService.description}</div>
            {hoveredService.techStack.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {hoveredService.techStack.map(t => (
                  <span key={t} className="text-[9px] px-1.5 py-0.5 rounded bg-surface-800 text-surface-400">
                    {t}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Zoom hint on fullscreen */}
        {isFullscreen && (
          <div className="absolute bottom-4 left-4 text-[10px] text-surface-600 flex items-center gap-3">
            <span>Scroll to zoom</span>
            <span>&middot;</span>
            <span>Drag background to pan</span>
            <span>&middot;</span>
            <span>Drag nodes to reposition</span>
            <span>&middot;</span>
            <span>Esc to exit</span>
          </div>
        )}
      </div>
    </div>
  )
}
