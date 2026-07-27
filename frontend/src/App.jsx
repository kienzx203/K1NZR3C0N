import React from 'react'
import { Routes, Route, NavLink, Navigate } from 'react-router-dom'
import Dashboard from './pages/Dashboard.jsx'
import Runs from './pages/Runs.jsx'
import RunDetail from './pages/RunDetail.jsx'
import Findings from './pages/Findings.jsx'
import Terminal from './pages/Terminal.jsx'
import Keys from './pages/Keys.jsx'
import Tools from './pages/Tools.jsx'
import Workflows from './pages/Workflows.jsx'
import WorkflowEditor from './pages/WorkflowEditor.jsx'

const NAV = [
  { to: '/',           label: '◆ Dashboard',  exact: true },
  { to: '/runs',       label: '▸ Runs' },
  { to: '/workflows',  label: '◈ Workflows' },
  { to: '/findings',   label: '⚑ Findings' },
  { to: '/terminal',   label: '⬡ Terminal' },
  { to: '/keys',       label: '⚷ Keys' },
  { to: '/tools',      label: '⚙ Tools' },
]

export default function App() {
  return (
    <div className="flex h-screen overflow-hidden bg-[#0d1117]">
      {/* Sidebar */}
      <aside className="w-52 flex-shrink-0 border-r border-[#30363d] flex flex-col">
        <div className="px-4 py-4 border-b border-[#30363d]">
          <span className="text-[#58a6ff] font-bold tracking-widest text-sm">k1nzr3c0n</span>
          <p className="text-[10px] text-[#8b949e] mt-0.5">security workflow runner</p>
        </div>
        <nav className="flex-1 py-3 space-y-0.5 px-2">
          {NAV.map(({ to, label, exact }) => (
            <NavLink
              key={to}
              to={to}
              end={exact}
              className={({ isActive }) =>
                `block px-3 py-2 rounded text-xs transition-colors ${
                  isActive
                    ? 'bg-[#58a6ff1a] text-[#58a6ff]'
                    : 'text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#161b22]'
                }`
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="px-4 py-3 border-t border-[#30363d]">
          <p className="text-[10px] text-[#8b949e]">v3.1.0</p>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-y-auto">
        <Routes>
          <Route path="/"                      element={<Dashboard />} />
          <Route path="/runs"                  element={<Runs />} />
          <Route path="/runs/:id"              element={<RunDetail />} />
          <Route path="/workflows"             element={<Workflows />} />
          <Route path="/workflows/:name"       element={<WorkflowEditor />} />
          <Route path="/findings"              element={<Findings />} />
          <Route path="/terminal"              element={<Terminal />} />
          <Route path="/keys"                  element={<Keys />} />
          <Route path="/tools"                 element={<Tools />} />
          <Route path="*"                      element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  )
}
