import { useState } from 'react'

interface AddProjectDialogProps {
  open: boolean
  onClose: () => void
  onAdd: (name: string, directory: string, devServerUrl: string) => void
}

export default function AddProjectDialog({ open, onClose, onAdd }: AddProjectDialogProps) {
  const [name, setName] = useState('')
  const [directory, setDirectory] = useState('')
  const [devServerUrl, setDevServerUrl] = useState('http://localhost:3000')

  if (!open) return null

  const handleAdd = () => {
    if (!name.trim() || !directory.trim()) return
    onAdd(name.trim(), directory.trim(), devServerUrl.trim())
    setName('')
    setDirectory('')
    setDevServerUrl('http://localhost:3000')
    onClose()
  }

  const handleBrowse = async () => {
    try {
      const result = await window.api.invoke('dialog:openDirectory') as string | null
      if (result) {
        setDirectory(result)
        if (!name.trim()) {
          setName(result.split('/').pop() || '')
        }
      }
    } catch {
      // Fallback — user types manually
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/70" onClick={onClose} />

      {/* Dialog */}
      <div className="relative bg-surface-900 border border-surface-700 rounded-card w-full max-w-md p-6 flex flex-col gap-5">
        <h2 className="text-lg font-bold text-white">Add Project</h2>

        <div className="flex flex-col gap-4">
          {/* Name */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] font-bold text-surface-500 uppercase tracking-wider">
              Project Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="my-app"
              className="bg-surface-950 border border-surface-800 rounded-input px-3 py-2.5
                text-sm text-white placeholder:text-surface-600
                focus:outline-none focus:border-surface-500 transition-colors"
            />
          </div>

          {/* Directory */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] font-bold text-surface-500 uppercase tracking-wider">
              Directory
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={directory}
                onChange={(e) => setDirectory(e.target.value)}
                placeholder="/Users/you/projects/my-app"
                className="flex-1 bg-surface-950 border border-surface-800 rounded-input px-3 py-2.5
                  text-sm text-white placeholder:text-surface-600 font-mono
                  focus:outline-none focus:border-surface-500 transition-colors"
              />
              <button
                onClick={handleBrowse}
                className="px-4 py-2.5 bg-surface-800 text-surface-300 text-sm font-bold rounded-btn
                  hover:bg-surface-700 transition-colors shrink-0"
              >
                Browse
              </button>
            </div>
          </div>

          {/* Dev Server URL */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] font-bold text-surface-500 uppercase tracking-wider">
              Dev Server URL
            </label>
            <input
              type="text"
              value={devServerUrl}
              onChange={(e) => setDevServerUrl(e.target.value)}
              placeholder="http://localhost:3000"
              className="bg-surface-950 border border-surface-800 rounded-input px-3 py-2.5
                text-sm text-white placeholder:text-surface-600 font-mono
                focus:outline-none focus:border-surface-500 transition-colors"
            />
          </div>
        </div>

        {/* Actions */}
        <div className="flex justify-end gap-3 pt-2">
          <button
            onClick={onClose}
            className="px-5 py-2.5 text-sm font-bold text-surface-400 hover:text-white transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleAdd}
            disabled={!name.trim() || !directory.trim()}
            className="px-6 py-2.5 bg-white text-black text-sm font-bold rounded-btn
              hover:bg-surface-200 transition-colors
              disabled:opacity-20 disabled:cursor-not-allowed uppercase tracking-wide"
          >
            Add
          </button>
        </div>
      </div>
    </div>
  )
}
