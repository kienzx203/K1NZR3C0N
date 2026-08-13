import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'

// Unified severity palette (matches components/SevBadge.jsx)
const SEV_COLOR = {
  critical: { bg: '#f8514916', text: '#f85149', border: '#f85149' },
  high:     { bg: '#f0883e16', text: '#f0883e', border: '#f0883e' },
  medium:   { bg: '#f0b42916', text: '#f0b429', border: '#f0b429' },
  low:      { bg: '#58a6ff16', text: '#58a6ff', border: '#58a6ff' },
  info:     { bg: '#9aa7b816', text: '#9aa7b8', border: '#9aa7b8' },
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

function SevBadge({ sev }) {
  const c = SEV_COLOR[sev] || SEV_COLOR.info
  return (
    <span style={{
      background: c.bg, color: c.text, border: `1px solid ${c.border}`,
      fontFamily: 'monospace', fontSize: 10, fontWeight: 700, letterSpacing: '.08em',
      padding: '2px 7px', borderRadius: 3, textTransform: 'uppercase',
    }}>
      {sev || 'info'}
    </span>
  )
}

export default function Findings() {
  const [stats, setStats] = useState(null)
  const [data, setData] = useState(null)
  const [filter, setFilter] = useState({ kind: '', severity: '', status: 'open', host: '' })
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    api.getFindingsStats().then(setStats).catch(() => {})
  }, [])

  useEffect(() => {
    setLoading(true)
    const params = { ...filter, limit: 200 }
    Object.keys(params).forEach(k => !params[k] && delete params[k])
    api.getFindings(params).then(res => { setData(res); setLoading(false) }).catch(() => setLoading(false))
  }, [filter])

  const changeStatus = async (id, status) => {
    await api.patchFinding(id, { status })
    setData(prev => prev ? { ...prev, items: prev.items.map(f => f.id === id ? { ...f, status } : f) } : prev)
  }

  const items = data?.items || []

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-lg font-bold text-[#e6edf3] font-mono mb-1">Findings</h1>
        <p className="text-xs text-[#8b949e]">Structured intel parsed from all run outputs</p>
      </div>

      {/* Stats row */}
      {stats && (
        <div className="flex gap-3 mb-6 flex-wrap">
          {['critical', 'high', 'medium', 'low', 'info'].map(s => {
            const n = stats.by_severity?.[s] || 0
            if (!n) return null
            const c = SEV_COLOR[s]
            return (
              <button
                key={s}
                onClick={() => setFilter(f => ({ ...f, severity: f.severity === s ? '' : s }))}
                style={{ background: c.bg, border: `1px solid ${filter.severity === s ? c.text : c.border}`, color: c.text }}
                className="rounded-lg px-4 py-2 text-center cursor-pointer transition-all"
              >
                <div className="text-xl font-bold font-mono">{n}</div>
                <div style={{ fontSize: 10, letterSpacing: '.08em', textTransform: 'uppercase', opacity: .8 }}>{s}</div>
              </button>
            )
          })}
          <div className="border border-[#30363d] rounded-lg px-4 py-2 text-center">
            <div className="text-xl font-bold font-mono text-[#e6edf3]">{stats.total}</div>
            <div className="text-[10px] text-[#8b949e] uppercase tracking-widest">Total</div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-2 mb-4 flex-wrap">
        <input
          className="input py-1.5 text-xs w-48"
          placeholder="Filter by host…"
          value={filter.host}
          onChange={e => setFilter(f => ({ ...f, host: e.target.value }))}
        />
        <select className="input py-1.5 text-xs" value={filter.kind} onChange={e => setFilter(f => ({ ...f, kind: e.target.value }))}>
          <option value="">All types</option>
          <option value="vuln">Vulnerability</option>
          <option value="port">Open Port</option>
          <option value="http">HTTP Service</option>
          <option value="subdomain">Subdomain</option>
        </select>
        <select className="input py-1.5 text-xs" value={filter.severity} onChange={e => setFilter(f => ({ ...f, severity: e.target.value }))}>
          <option value="">All severities</option>
          {['critical','high','medium','low','info'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="input py-1.5 text-xs" value={filter.status} onChange={e => setFilter(f => ({ ...f, status: e.target.value }))}>
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="fp">False positive</option>
          <option value="resolved">Resolved</option>
        </select>
        <span className="text-xs text-[#8b949e] self-center ml-auto">{data?.total ?? '—'} results</span>
      </div>

      {/* Table */}
      <div className="border border-[#30363d] rounded-lg overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-[#30363d] bg-[#161b22]">
              <th className="text-left px-4 py-2 text-[#8b949e] font-medium">Severity</th>
              <th className="text-left px-4 py-2 text-[#8b949e] font-medium">Type</th>
              <th className="text-left px-4 py-2 text-[#8b949e] font-medium">Name / Template</th>
              <th className="text-left px-4 py-2 text-[#8b949e] font-medium">Host</th>
              <th className="text-left px-4 py-2 text-[#8b949e] font-medium">Run</th>
              <th className="text-left px-4 py-2 text-[#8b949e] font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={6} className="text-center py-8 text-[#8b949e]">Loading…</td></tr>
            )}
            {!loading && items.length === 0 && (
              <tr><td colSpan={6} className="text-center py-12 text-[#8b949e]">
                No findings match the current filter.
                {data?.total === 0 && <div className="mt-2 text-[11px]">Run a workflow with nuclei, httpx or naabu steps to start populating findings.</div>}
              </td></tr>
            )}
            {!loading && items.map(f => (
              <tr key={f.id} className="border-b border-[#21262d] hover:bg-[#161b22] transition-colors">
                <td className="px-4 py-2"><SevBadge sev={f.severity} /></td>
                <td className="px-4 py-2 font-mono text-[#8b949e]">{f.kind}</td>
                <td className="px-4 py-2 max-w-xs">
                  <div className="truncate text-[#e6edf3]">{f.name || f.template_id || f.host}</div>
                  {f.template_id && f.name && <div className="text-[10px] text-[#8b949e] font-mono truncate">{f.template_id}</div>}
                </td>
                <td className="px-4 py-2 font-mono max-w-[200px] truncate" title={f.host}>{f.host}</td>
                <td className="px-4 py-2">
                  <Link to={`/runs/${f.run_id}`} className="text-[#58a6ff] hover:underline font-mono">
                    {f.run_id}
                  </Link>
                </td>
                <td className="px-4 py-2">
                  <select
                    value={f.status}
                    onChange={e => changeStatus(f.id, e.target.value)}
                    className="bg-transparent text-[10px] font-mono border border-[#30363d] rounded px-1.5 py-0.5 cursor-pointer text-[#8b949e]"
                  >
                    <option value="open">OPEN</option>
                    <option value="fp">FALSE+</option>
                    <option value="resolved">RESOLVED</option>
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
