import { create } from 'zustand'
import type { Task, TaskStatus } from '@shared/types'

interface TaskStore {
  tasks: Task[]
  addTask: (task: Task) => void
  updateTask: (id: string, updates: Partial<Task>) => void
  removeTask: (id: string) => void
  setTaskStatus: (id: string, status: TaskStatus) => void
  getQueued: () => Task[]
  getRunning: () => Task[]
}

export const useTaskStore = create<TaskStore>((set, get) => ({
  tasks: [],

  addTask: (task) => set((s) => ({ tasks: [...s.tasks, task] })),

  updateTask: (id, updates) =>
    set((s) => ({
      tasks: s.tasks.map((t) => (t.id === id ? { ...t, ...updates } : t))
    })),

  removeTask: (id) =>
    set((s) => ({ tasks: s.tasks.filter((t) => t.id !== id) })),

  setTaskStatus: (id, status) =>
    set((s) => ({
      tasks: s.tasks.map((t) => (t.id === id ? { ...t, status } : t))
    })),

  getQueued: () => get().tasks.filter((t) => t.status === 'queued'),
  getRunning: () => get().tasks.filter((t) => t.status === 'running')
}))
