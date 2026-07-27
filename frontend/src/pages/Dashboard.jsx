import React, { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api.js'
import { formatDuration, timeAgo, durSecs } from '../utils.js'
import NewRunModal from '../components/NewRunModal.jsx'

const SEV_META = [
  { key: 'critical', label: 'Critical', color: '#ff4444' },
  { key: 'high',     label: 'High',     color: '#f85149' },
  { key: 'medium',   label: 'Medium',   color: '#f0b429' },
  { key: 'low',      label: 'Low',      color: '#58a6ff' },
]

function StatCard({ label, value, color, sub, to }) {
  const navigate = useNavigate()
  const inner = (
    <div
      className={`card p-4 ${to ? 'cursor-pointer hover:border-[#58a6ff44] transition-colors' : ''}`}
      onClick={to ? () => navigate(to) : undefined}
    >
      <p className="text-[10px] uppercase tracking-wider text-[#8b949e] mb-1">{label}</p>
      <p className={`text-3xl font-bold font-mono ${color || 'text-[#e6edf3]'}`}>{value ?? '—'}</p>
      {sub && <p className="text-[10px] text-[#484f58] mt-1">{sub}</p>}
    </div>
  )
  return inner
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [showModal, setShowModal] = useState(false)

  useEffect(() => {
    const load = () => api.getStats().then(setStats).catch(() => {})
    load()
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [])

  if (!stats) return (
    <div className="p-8 flex items-center gap-2 text-[#8b949e] text-sm">
      <span className="animate-pulse">●</span> Loading…
    </div>
  )

  const { total, by_status, findings, recent } = stats
  const bySev = findings?.by_severity || {}
  const hasSevData = SEV_META.some(s => bySev[s.key] > 0)

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold text-[#e6edf3]">Dashboard</h1>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>+ New Run</button>
      </div>

      {/* Run status cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <StatCard label="Total Runs"  value={total}                 to="/runs" />
        <StatCard label="Running"     value={by_status.running}     color="text-[#3fb950]" to="/runs?status=running" />
        <StatCard label="Queued"      value={by_status.queued}      color="text-[#8b949e]" to="/runs?status=queued" />
        <StatCard label="Completed"   value={by_status.completed}   color="text-[#3fb950]" to="/runs?status=completed" />
        <StatCard label="Failed"      value={by_status.failed}      color="text-[#f85149]" to="/runs?status=failed" />
      </div>

      {/* Findings severity breakdown */}
      {findings?.total > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-3">
            <h2 className="text-xs font-semibold text-[#e6edf3] uppercase tracking-wider">Findings</h2>
            <span className="text-[10px] text-[#8b949e]">
              {findings.total} total · {findings.open_vulns} open vulns
            </span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {SEV_META.map(({ key, label, color }) => (
              <div key={key} className="card p-4" style={{ borderColor: bySev[key] ? color + '44' : undefined }}>
                <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: bySev[key] ? color : '#484f58' }}>{label}</p>
                <p className="text-2xl font-bold font-mono" style={{ color: bySev[key] ? color : '#484f58' }}>
                  {bySev[key] ?? 0}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent runs */}
      <div className="card overflow-hidden">
        <div className="px-4 py-3 border-b border-[#30363d] flex items-center justify-between">
          <h2 className="text-xs font-semibold text-[#e6edf3] uppercase tracking-wider">Recent Runs</h2>
          <Link to="/runs" className="text-[10px] text-[#58a6ff] hover:underline">View all →</Link>
        </div>
        {recent.length === 0 ? (
          <div className="p-8 text-center">
            <p className="text-[#8b949e] text-sm mb-3">No runs yet.</p>
            <button className="btn btn-primary" onClick={() => setShowModal(true)}>Start your first scan</button>
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#30363d]">
                {['Target', 'Status', 'Duration', 'Started'].map(h => (
                  <th key={h} className="px-4 py-2 text-left text-[#8b949e] uppercase text-[10px] tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {recent.map(r => (
                <tr key={r.id} className="border-b border-[#30363d] last:border-0 hover:bg-[#161b22] transition-colors">
                  <td className="px-4 py-2.5">
                    <Link to={`/runs/${r.id}`} className="text-[#58a6ff] hover:underline font-mono">{r.target}</Link>
                    <span className="ml-2 text-[#484f58] text-[10px]">{r.workflow}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`badge badge-${r.status}`}>{r.status}</span>
                  </td>
                  <td className="px-4 py-2.5 text-[#8b949e] font-mono">
                    {r.status === 'running' ? <span className="text-[#3fb950] animate-pulse">running…</span>
                      : formatDuration(durSecs(r))}
                  </td>
                  <td className="px-4 py-2.5 text-[#8b949e]" title={r.created_at}>
                    {timeAgo(r.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showModal && <NewRunModal onClose={() => setShowModal(false)} onCreated={() => setShowModal(false)} />}
    </div>
  )
}
