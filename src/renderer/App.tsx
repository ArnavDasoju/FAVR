import { useState } from 'react'
import Sidebar, { type View } from './components/Sidebar'
import Dashboard from './components/Dashboard'
import AgentRoster from './components/AgentRoster'
import FlowsView from './components/FlowsView'
import BudgetView from './components/BudgetView'
import Settings from './components/Settings'
import { useIpcListeners } from './hooks/useIpc'

declare global {
  interface Window {
    api: {
      invoke: (channel: string, ...args: unknown[]) => Promise<unknown>
      on: (channel: string, callback: (...args: unknown[]) => void) => () => void
    }
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
      case 'flows':
        return <FlowsView />
      case 'budget':
        return <BudgetView />
      case 'settings':
        return <Settings />
    }
  }

  return (
    <div className="h-full w-full flex bg-surface-950">
      <Sidebar
        activeView={activeView}
        onNavigate={setActiveView}
        budget={{ spent: 23.40, limit: 50 }}
        agentCount={3}
        activeFlows={1}
      />
      <div className="flex-1 overflow-hidden flex flex-col">
        {/* Titlebar drag region for main content area */}
        <div className="titlebar-drag h-12 shrink-0" />
        <div className="flex-1 overflow-hidden">
          {renderView()}
        </div>
      </div>
    </div>
  )
}
