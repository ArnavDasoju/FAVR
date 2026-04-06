import { useState, Component, type ReactNode } from 'react'
import Sidebar, { type View } from './components/Sidebar'
import Dashboard from './components/Dashboard'
import AgentRoster from './components/AgentRoster'
import FlowsView from './components/FlowsView'
import BudgetView from './components/BudgetView'
import Settings from './components/Settings'
import Stats from './components/Stats'
import { useIpcListeners } from './hooks/useIpc'

declare global {
  interface Window {
    api: {
      invoke: (channel: string, ...args: unknown[]) => Promise<unknown>
      on: (channel: string, callback: (...args: unknown[]) => void) => () => void
    }
  }
}

class ViewErrorBoundary extends Component<{ children: ReactNode }, { error: string | null }> {
  state = { error: null as string | null }
  static getDerivedStateFromError(err: Error) {
    return { error: err.message }
  }
  render() {
    if (this.state.error) {
      return (
        <div className="h-full flex items-center justify-center p-8">
          <div className="bg-surface-900 border border-red-500/30 rounded-card p-6 max-w-md">
            <p className="text-red-400 font-bold text-sm mb-2">Something went wrong</p>
            <p className="text-xs text-surface-400 font-mono">{this.state.error}</p>
            <button
              onClick={() => this.setState({ error: null })}
              className="mt-4 text-xs text-white bg-surface-800 px-3 py-1.5 rounded hover:bg-surface-700"
            >
              Try again
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

export default function App() {
  useIpcListeners()
  const [activeView, setActiveView] = useState<View>('dashboard')

  const renderView = () => {
    switch (activeView) {
      case 'dashboard':
        return <Dashboard />
      case 'agents':
        return <AgentRoster />
      case 'vulnerabilities':
        return <FlowsView />
      case 'analysis':
        return <BudgetView />
      case 'comparison':
        return <Stats />
      case 'settings':
        return <Settings />
    }
  }

  return (
    <div className="h-full w-full flex bg-surface-950">
      <Sidebar activeView={activeView} onNavigate={setActiveView} />
      <div className="flex-1 overflow-hidden flex flex-col">
        <div className="titlebar-drag h-12 shrink-0" />
        <div className="flex-1 overflow-hidden">
          <ViewErrorBoundary key={activeView}>
            {renderView()}
          </ViewErrorBoundary>
        </div>
      </div>
    </div>
  )
}
