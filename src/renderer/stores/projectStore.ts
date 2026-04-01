import { create } from 'zustand'
import type { Project } from '@shared/types'

interface ProjectStore {
  projects: Project[]
  activeProjectId: string | null
  addProject: (project: Project) => void
  removeProject: (id: string) => void
  setActiveProject: (id: string) => void
  getActiveProject: () => Project | null
}

export const useProjectStore = create<ProjectStore>((set, get) => ({
  projects: [],
  activeProjectId: null,

  addProject: (project) =>
    set((s) => ({
      projects: [...s.projects, project],
      activeProjectId: s.activeProjectId ?? project.id
    })),

  removeProject: (id) =>
    set((s) => ({
      projects: s.projects.filter((p) => p.id !== id),
      activeProjectId: s.activeProjectId === id ? (s.projects[0]?.id ?? null) : s.activeProjectId
    })),

  setActiveProject: (id) => set({ activeProjectId: id }),

  getActiveProject: () => {
    const { projects, activeProjectId } = get()
    return projects.find((p) => p.id === activeProjectId) ?? null
  }
}))
