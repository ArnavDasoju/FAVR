import type { Task } from '@shared/types'

const statusStyles: Record<string, string> = {
  queued: 'text-surface-500',
  chunking: 'text-surface-400',
  running: 'text-white',
  validating: 'text-surface-300',
  retrying: 'text-surface-300',
  needs_review: 'text-white',
  approved: 'text-surface-400',
  rejected: 'text-surface-600'
}

interface TaskQueueProps {
  tasks: Task[]
  onCancel?: (id: string) => void
}

export default function TaskQueue({ tasks, onCancel }: TaskQueueProps) {
  if (tasks.length === 0) return null

  return (
    <div className="bg-surface-900 border border-surface-800 rounded-card overflow-hidden">
      <div className="px-4 py-3 border-b border-surface-800/50">
        <span className="text-[10px] font-bold text-surface-500 uppercase tracking-[0.2em]">
          Queue
        </span>
      </div>

      <div className="divide-y divide-surface-800/30">
        {tasks.map((task, i) => (
          <div
            key={task.id}
            className="px-4 py-3 flex items-center gap-4 hover:bg-surface-800/30 transition-colors"
          >
            <span className="text-[10px] font-mono text-surface-600 w-4 text-right">
              {i + 1}
            </span>
            <span className="text-sm text-surface-300 flex-1 truncate">
              {task.prompt}
            </span>
            <span className="text-[10px] font-mono text-surface-600 uppercase tracking-wider">
              {task.model?.split('/').pop() || 'auto'}
            </span>
            <span className={`text-[10px] font-bold uppercase tracking-wider ${statusStyles[task.status]}`}>
              {task.status}
            </span>
            {(task.status === 'queued' || task.status === 'running') && onCancel && (
              <button
                onClick={() => onCancel(task.id)}
                className="text-[10px] text-surface-600 hover:text-white transition-colors
                  font-bold uppercase tracking-wider"
              >
                Cancel
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
