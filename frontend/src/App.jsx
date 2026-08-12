import React from 'react'
import { Routes, Route, NavLink, Navigate } from 'react-router-dom'
import Dashboard from './pages/Dashboard.jsx'
import Runs from './pages/Runs.jsx'
import RunDetail from './pages/RunDetail.jsx'
import Findings from './pages/Findings.jsx'
import Inventory from './pages/Inventory.jsx'
import Terminal from './pages/Terminal.jsx'
import Keys from './pages/Keys.jsx'
import Tools from './pages/Tools.jsx'
import Workflows from './pages/Workflows.jsx'
import WorkflowEditor from './pages/WorkflowEditor.jsx'
import Upload from './pages/Upload.jsx'
import { getTheme, applyTheme } from './theme.js'

const NAV = [
  { to: '/',           label: '◆ Dashboard',  exact: true },
  { to: '/runs',       label: '▸ Runs' },
  { to: '/workflows',  label: '◈ Workflows' },
  { to: '/findings',   label: '⚑ Findings' },
  { to: '/inventory',  label: '▤ Inventory' },
  { to: '/upload',     label: '↑ Upload' },
  { to: '/terminal',   label: '⬡ Terminal' },
  { to: '/keys',       label: '⚷ Keys' },
  { to: '/tools',      label: '⚙ Tools' },
]

const NAV_EXTERNAL = [
  { href: 'http://127.0.0.1:4040/', label: '✦ OpenCode' },
]

export default function App() {
  const [theme, setTheme] = React.useState(getTheme())
  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    applyTheme(next)
    setTheme(next)
  }

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
          <div className="pt-2 mt-2 border-t border-[#30363d]">
            {NAV_EXTERNAL.map(({ href, label }) => (
              <a
                key={href}
                href={href}
                target="_blank"
                rel="noopener noreferrer"
                className="block px-3 py-2 rounded text-xs transition-colors text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#161b22]"
              >
                {label}
              </a>
            ))}
          </div>
        </nav>
        <div className="px-4 py-3 border-t border-[#30363d] flex items-center justify-between">
          <p className="text-[10px] text-[#8b949e]">v3.1.0</p>
          <button
            onClick={toggleTheme}
            className="text-[10px] text-[#8b949e] hover:text-[#e6edf3] px-1.5 py-0.5 rounded hover:bg-[#161b22] transition-colors"
            title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
          >
            {theme === 'dark' ? '☀' : '🌙'}
          </button>
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
          <Route path="/inventory"             element={<Inventory />} />
          <Route path="/upload"                element={<Upload />} />
          <Route path="/terminal"              element={<Terminal />} />
          <Route path="/keys"                  element={<Keys />} />
          <Route path="/tools"                 element={<Tools />} />
          <Route path="*"                      element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  )
}
