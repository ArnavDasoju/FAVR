/**
 * DiffViewer — displays code diffs with syntax-highlighted additions/deletions.
 */

interface DiffViewerProps {
  diff: string
  compact?: boolean
}

interface DiffFile {
  path: string
  hunks: DiffHunk[]
}

interface DiffHunk {
  header: string
  lines: DiffLine[]
}

interface DiffLine {
  type: 'add' | 'remove' | 'context'
  content: string
  oldNum: number | null
  newNum: number | null
}

function parseDiff(raw: string): DiffFile[] {
  const files: DiffFile[] = []
  const lines = raw.split('\n')
  let currentFile: DiffFile | null = null
  let currentHunk: DiffHunk | null = null
  let oldLine = 0
  let newLine = 0

  for (const line of lines) {
    // File header
    if (line.startsWith('diff --git') || line.startsWith('--- ') || line.startsWith('+++ ')) {
      if (line.startsWith('+++ ')) {
        const path = line.slice(6) // remove '+++ b/'
        currentFile = { path: path || 'unknown', hunks: [] }
        files.push(currentFile)
      }
      continue
    }

    // Hunk header
    const hunkMatch = line.match(/^@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@(.*)/)
    if (hunkMatch) {
      oldLine = parseInt(hunkMatch[1])
      newLine = parseInt(hunkMatch[2])
      currentHunk = { header: line, lines: [] }
      currentFile?.hunks.push(currentHunk)
      continue
    }

    if (!currentHunk) continue

    if (line.startsWith('+')) {
      currentHunk.lines.push({ type: 'add', content: line.slice(1), oldNum: null, newNum: newLine++ })
    } else if (line.startsWith('-')) {
      currentHunk.lines.push({ type: 'remove', content: line.slice(1), oldNum: oldLine++, newNum: null })
    } else {
      currentHunk.lines.push({ type: 'context', content: line.slice(1) || line, oldNum: oldLine++, newNum: newLine++ })
    }
  }

  return files
}

export default function DiffViewer({ diff, compact = false }: DiffViewerProps) {
  if (!diff || diff.trim().length === 0) {
    return (
      <div className="bg-surface-950 rounded p-4 text-center">
        <span className="text-xs text-surface-600">No changes to display</span>
      </div>
    )
  }

  const files = parseDiff(diff)

  if (files.length === 0) {
    // Raw diff without proper git headers — just show it
    return (
      <div className="bg-surface-950 rounded overflow-hidden">
        <pre className="text-[11px] font-mono text-surface-400 p-3 overflow-x-auto whitespace-pre">
          {diff}
        </pre>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-3">
      {/* File list summary */}
      {!compact && (
        <div className="flex flex-wrap gap-2">
          {files.map((file, i) => {
            const adds = file.hunks.reduce((sum, h) => sum + h.lines.filter((l) => l.type === 'add').length, 0)
            const dels = file.hunks.reduce((sum, h) => sum + h.lines.filter((l) => l.type === 'remove').length, 0)
            return (
              <span
                key={i}
                className="text-[10px] font-mono bg-surface-900 border border-surface-800 px-2 py-1 rounded flex items-center gap-2"
              >
                <span className="text-surface-300">{file.path}</span>
                {adds > 0 && <span className="text-green-400">+{adds}</span>}
                {dels > 0 && <span className="text-red-400">-{dels}</span>}
              </span>
            )
          })}
        </div>
      )}

      {/* Diff content */}
      {files.map((file, fi) => (
        <div key={fi} className="bg-surface-950 border border-surface-800/50 rounded overflow-hidden">
          <div className="px-3 py-2 bg-surface-900/50 border-b border-surface-800/50">
            <span className="text-[11px] font-mono text-surface-400">{file.path}</span>
          </div>

          {file.hunks.map((hunk, hi) => (
            <div key={hi}>
              <div className="px-3 py-1 bg-surface-900/30 border-b border-surface-800/30">
                <span className="text-[10px] font-mono text-surface-600">{hunk.header}</span>
              </div>

              <div className="font-mono text-[11px] leading-[1.6]">
                {hunk.lines.map((line, li) => (
                  <div
                    key={li}
                    className={`flex ${
                      line.type === 'add'
                        ? 'bg-green-950/30'
                        : line.type === 'remove'
                          ? 'bg-red-950/30'
                          : ''
                    }`}
                  >
                    {/* Line numbers */}
                    <span className="w-10 shrink-0 text-right pr-2 text-surface-700 select-none border-r border-surface-800/30">
                      {line.oldNum ?? ''}
                    </span>
                    <span className="w-10 shrink-0 text-right pr-2 text-surface-700 select-none border-r border-surface-800/30">
                      {line.newNum ?? ''}
                    </span>

                    {/* +/- indicator */}
                    <span
                      className={`w-5 shrink-0 text-center select-none ${
                        line.type === 'add'
                          ? 'text-green-400'
                          : line.type === 'remove'
                            ? 'text-red-400'
                            : 'text-transparent'
                      }`}
                    >
                      {line.type === 'add' ? '+' : line.type === 'remove' ? '-' : ' '}
                    </span>

                    {/* Content */}
                    <span
                      className={`flex-1 px-2 whitespace-pre overflow-x-auto ${
                        line.type === 'add'
                          ? 'text-green-300'
                          : line.type === 'remove'
                            ? 'text-red-300'
                            : 'text-surface-400'
                      }`}
                    >
                      {line.content}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      ))}
    </div>
  )
}
