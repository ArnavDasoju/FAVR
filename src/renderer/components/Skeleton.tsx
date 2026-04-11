/**
 * Skeleton loading components — shimmer placeholders for loading states.
 */

// ─── Base skeleton block ──────────────────────────────────────
export function Skeleton({ className = '', style }: { className?: string; style?: React.CSSProperties }) {
  return <div className={`animate-shimmer rounded-btn ${className}`} style={style} />
}

// ─── Stat card skeleton ───────────────────────────────────────
export function StatCardSkeleton() {
  return (
    <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
      <div className="flex items-center gap-1.5 mb-3">
        <Skeleton className="w-3.5 h-3.5 rounded-full" />
        <Skeleton className="w-16 h-2" />
      </div>
      <Skeleton className="w-20 h-7 mb-2" />
      <Skeleton className="w-24 h-2" />
    </div>
  )
}

// ─── Chart skeleton (generic) ─────────────────────────────────
export function ChartSkeleton({ height = 280, title }: { height?: number; title?: string }) {
  return (
    <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
      {title && (
        <>
          <Skeleton className="w-32 h-4 mb-1" />
          <Skeleton className="w-48 h-2 mb-4" />
        </>
      )}
      <div className="relative overflow-hidden rounded-btn" style={{ height }}>
        {/* Fake axis lines */}
        <div className="absolute inset-0 flex flex-col justify-between py-4 pr-4">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="border-b border-surface-800/50" />
          ))}
        </div>
        {/* Fake bars / chart area */}
        <div className="absolute bottom-4 left-8 right-4 flex items-end gap-3 h-3/4">
          {[65, 85, 45, 70, 55, 90, 40, 75].map((h, i) => (
            <div key={i} className="flex-1 animate-shimmer rounded-t-sm" style={{ height: `${h}%`, animationDelay: `${i * 100}ms` }} />
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Dependency graph skeleton ────────────────────────────────
export function GraphSkeleton() {
  return (
    <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
      <div className="flex items-center justify-between mb-3">
        <div>
          <Skeleton className="w-36 h-4 mb-1" />
          <Skeleton className="w-52 h-2" />
        </div>
        <Skeleton className="w-8 h-8 rounded-btn" />
      </div>
      <div className="relative overflow-hidden rounded-btn" style={{ height: 300 }}>
        {/* Fake nodes */}
        {[
          { x: '20%', y: '30%', size: 40 },
          { x: '55%', y: '20%', size: 36 },
          { x: '75%', y: '45%', size: 44 },
          { x: '35%', y: '60%', size: 38 },
          { x: '60%', y: '70%', size: 32 },
        ].map((node, i) => (
          <div
            key={i}
            className="absolute animate-shimmer rounded-full"
            style={{
              left: node.x,
              top: node.y,
              width: node.size,
              height: node.size,
              animationDelay: `${i * 200}ms`,
            }}
          />
        ))}
        {/* Fake edges */}
        <svg className="absolute inset-0 w-full h-full" style={{ opacity: 0.15 }}>
          <line x1="22%" y1="35%" x2="55%" y2="25%" stroke="#3f3f46" strokeWidth="1.5" />
          <line x1="55%" y1="25%" x2="75%" y2="48%" stroke="#3f3f46" strokeWidth="1.5" />
          <line x1="22%" y1="35%" x2="37%" y2="63%" stroke="#3f3f46" strokeWidth="1.5" />
          <line x1="37%" y1="63%" x2="62%" y2="73%" stroke="#3f3f46" strokeWidth="1.5" />
          <line x1="75%" y1="48%" x2="62%" y2="73%" stroke="#3f3f46" strokeWidth="1.5" />
        </svg>
      </div>
    </div>
  )
}

// ─── Vulnerability row skeleton ───────────────────────────────
export function VulnRowSkeleton({ index = 0 }: { index?: number }) {
  return (
    <div
      className="bg-surface-900 border border-surface-800 rounded-card p-4 flex items-center gap-4"
      style={{ animationDelay: `${index * 60}ms` }}
    >
      <Skeleton className="w-8 h-8 rounded-full shrink-0" />
      <Skeleton className="w-16 h-5 rounded shrink-0" />
      <div className="flex-1 min-w-0">
        <Skeleton className="w-28 h-3.5 mb-2" />
        <Skeleton className="w-48 h-2.5" />
      </div>
      <Skeleton className="w-12 h-8 rounded shrink-0" />
      <Skeleton className="w-12 h-8 rounded shrink-0" />
    </div>
  )
}

// ─── Service heatmap skeleton ─────────────────────────────────
export function HeatmapSkeleton() {
  return (
    <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
      <Skeleton className="w-36 h-4 mb-1" />
      <Skeleton className="w-48 h-2 mb-4" />
      <div className="flex flex-col gap-2">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="flex items-center gap-3 rounded-btn p-3" style={{ animationDelay: `${i * 80}ms` }}>
            <Skeleton className="w-2 h-8 rounded-full shrink-0" />
            <div className="flex-1">
              <Skeleton className="w-28 h-3 mb-1.5" />
              <Skeleton className="w-40 h-2" />
            </div>
            <Skeleton className="w-12 h-6 shrink-0" />
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Priority patches skeleton ────────────────────────────────
export function PatchListSkeleton() {
  return (
    <div className="bg-surface-900 border border-surface-800 rounded-card p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Skeleton className="w-4 h-4 rounded" />
          <Skeleton className="w-32 h-4" />
          <Skeleton className="w-20 h-4 rounded-full" />
        </div>
        <Skeleton className="w-24 h-3" />
      </div>
      <div className="grid gap-2">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="flex items-center gap-3 bg-surface-800/40 rounded-btn p-3" style={{ animationDelay: `${i * 70}ms` }}>
            <Skeleton className="w-7 h-7 rounded-full shrink-0" />
            <Skeleton className="w-16 h-4 rounded shrink-0" />
            <div className="flex-1 min-w-0">
              <Skeleton className="w-24 h-3 mb-1.5" />
              <Skeleton className="w-44 h-2" />
            </div>
            <Skeleton className="w-10 h-6 shrink-0" />
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Full dashboard skeleton ──────────────────────────────────
export function DashboardSkeleton() {
  return (
    <div className="h-full overflow-y-auto p-6 animate-fadeIn">
      {/* Hero stats */}
      <div className="grid grid-cols-12 gap-4 mb-6">
        <div className="col-span-3 bg-surface-900 border border-surface-800 rounded-card p-5 flex flex-col items-center justify-center">
          <Skeleton className="w-[110px] h-[110px] rounded-full" />
          <Skeleton className="w-20 h-2 mt-3" />
        </div>
        <div className="col-span-9 grid grid-cols-5 gap-3">
          {[...Array(5)].map((_, i) => (
            <StatCardSkeleton key={i} />
          ))}
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        <GraphSkeleton />
        <HeatmapSkeleton />
      </div>

      {/* Priority patches */}
      <PatchListSkeleton />
    </div>
  )
}

// ─── Schedule skeleton ────────────────────────────────────────
export function ScheduleSkeleton() {
  return (
    <div className="flex flex-col gap-4 px-6 pb-6 animate-fadeIn">
      {[...Array(3)].map((_, w) => (
        <div key={w} className="bg-surface-900 border border-surface-800 rounded-card overflow-hidden" style={{ animationDelay: `${w * 100}ms` }}>
          <div className="px-5 py-3 border-b border-surface-800/50 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Skeleton className="w-16 h-4" />
              <Skeleton className="w-20 h-2" />
            </div>
            <Skeleton className="w-24 h-2" />
          </div>
          <div className="px-5 py-3 flex flex-col gap-3">
            {[...Array(2)].map((_, p) => (
              <div key={p}>
                <div className="flex items-center gap-3 mb-1.5">
                  <Skeleton className="w-14 h-4 rounded" />
                  <Skeleton className="w-24 h-3" />
                  <Skeleton className="flex-1 h-2" />
                  <Skeleton className="w-20 h-4 rounded" />
                </div>
                <Skeleton className="h-6 rounded-btn" />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
