import { useAnalysisStore } from '../../stores/analysisStore'

const TIER_COLORS: Record<string, string> = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#EAB308',
  low: '#3B82F6'
}

// Predefined positions for 5 services (center layout)
const POSITIONS: Record<string, { x: number; y: number }> = {
  'auth-service': { x: 300, y: 60 },
  'payment-api': { x: 150, y: 160 },
  'customer-portal': { x: 450, y: 160 },
  'database-layer': { x: 300, y: 260 },
  'internal-dashboard': { x: 500, y: 280 }
}

// Fallback positions for arbitrary services
function getPosition(id: string, index: number, total: number): { x: number; y: number } {
  if (POSITIONS[id]) return POSITIONS[id]
  const angle = (2 * Math.PI * index) / total - Math.PI / 2
  return {
    x: 300 + Math.cos(angle) * 150,
    y: 170 + Math.sin(angle) * 120
  }
}

export default function DependencyGraph() {
  const result = useAnalysisStore(s => s.result)
  if (!result) return null

  const { services, dependencies } = result.graph
  const positions = new Map<string, { x: number; y: number }>()

  services.forEach((s, i) => {
    positions.set(s.id, getPosition(s.id, i, services.length))
  })

  return (
    <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
      <h3 className="text-sm font-bold text-white mb-1">Service Dependency Graph</h3>
      <p className="text-[10px] text-surface-500 mb-3">Arrows show dependency direction · Color = risk tier</p>
      <svg viewBox="0 0 600 340" className="w-full" style={{ maxHeight: '340px' }}>
        <defs>
          <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
            <polygon points="0 0, 8 3, 0 6" fill="#71717A" />
          </marker>
        </defs>

        {/* Edges */}
        {dependencies.map((dep, i) => {
          const from = positions.get(dep.from)
          const to = positions.get(dep.to)
          if (!from || !to) return null

          // Offset the line to not overlap with node circles
          const dx = to.x - from.x
          const dy = to.y - from.y
          const dist = Math.sqrt(dx * dx + dy * dy)
          const offsetFrom = 35 / dist
          const offsetTo = 35 / dist

          const x1 = from.x + dx * offsetFrom
          const y1 = from.y + dy * offsetFrom
          const x2 = to.x - dx * offsetTo
          const y2 = to.y - dy * offsetTo

          return (
            <g key={i}>
              <line
                x1={x1} y1={y1} x2={x2} y2={y2}
                stroke="#3F3F46"
                strokeWidth={Math.max(1, dep.propagationWeight * 3)}
                markerEnd="url(#arrowhead)"
                opacity={0.6}
              />
              <text
                x={(x1 + x2) / 2}
                y={(y1 + y2) / 2 - 6}
                fill="#52525B"
                fontSize="8"
                textAnchor="middle"
              >
                {dep.type}
              </text>
            </g>
          )
        })}

        {/* Nodes */}
        {services.map(service => {
          const pos = positions.get(service.id)!
          const risk = result.riskScores[service.id] ?? 0
          const color = TIER_COLORS[service.tier] ?? '#666'
          const vulnCount = result.graph.vulnerabilities.filter(v =>
            v.affectedServiceIds.includes(service.id)
          ).length

          return (
            <g key={service.id}>
              {/* Glow */}
              <circle cx={pos.x} cy={pos.y} r={32} fill={color} opacity={0.1} />
              {/* Ring */}
              <circle cx={pos.x} cy={pos.y} r={28} fill="#18181B" stroke={color} strokeWidth={2} />
              {/* Risk fill */}
              <circle cx={pos.x} cy={pos.y} r={24} fill={color} opacity={risk * 0.5} />
              {/* Label */}
              <text x={pos.x} y={pos.y - 4} fill="white" fontSize="9" fontWeight="bold" textAnchor="middle">
                {service.name.split(' ').map(w => w[0]).join('')}
              </text>
              <text x={pos.x} y={pos.y + 8} fill="#A1A1AA" fontSize="8" textAnchor="middle">
                {Math.round(risk * 100)}%
              </text>
              {/* Name below */}
              <text x={pos.x} y={pos.y + 46} fill="#71717A" fontSize="9" textAnchor="middle">
                {service.name}
              </text>
              {/* Vuln badge */}
              {vulnCount > 0 && (
                <>
                  <circle cx={pos.x + 22} cy={pos.y - 22} r={9} fill="#18181B" stroke={color} strokeWidth={1.5} />
                  <text x={pos.x + 22} y={pos.y - 18} fill={color} fontSize="9" fontWeight="bold" textAnchor="middle">
                    {vulnCount}
                  </text>
                </>
              )}
            </g>
          )
        })}
      </svg>
    </div>
  )
}
