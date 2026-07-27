import React, { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { formatDuration, timeAgo, durSecs } from '../utils.js'
import NewRunModal from '../components/NewRunModal.jsx'

const STATUSES = ['', 'queued', 'running', 'paused', 'completed', 'failed', 'cancelled']

export default function Runs() {
  const [data, setData]         = useState({ total: 0, items: [] })
  const [status, setStatus]     = useState('')
  const [search, setSearch]     = useState('')
  const [showModal, setShowModal] = useState(false)
  const [page, setPage]         = useState(0)
  const [selected, setSelected] = useState(new Set())
  const [deleting, setDeleting] = useState(false)
  const PAGE = 30

  const load = useCallback(() => {
    api.getRuns({ status: status || undefined, limit: PAGE, offset: page * PAGE })
      .then(setData).catch(() => {})
  }, [status, page])

  useEffect(() => { load(); const t = setInterval(load, 4000); return () => clearInterval(t) }, [load])

  // Clear selection when filter/page changes
  useEffect(() => { setSelected(new Set()) }, [status, search, page])

  const filtered = search
    ? data.items.filter(r => r.target.includes(search) || r.workflow.includes(search))
    : data.items

  const allChecked  = filtered.length > 0 && filtered.every(r => selected.has(r.id))
  const someChecked = selected.size > 0 && !allChecked

  function toggleAll() {
    if (allChecked) setSelected(new Set())
    else setSelected(new Set(filtered.map(r => r.id)))
  }

  function toggleOne(id) {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  async function deleteSelected() {
    if (!window.confirm(`Delete ${selected.size} run(s)? This cannot be undone.`)) return
    setDeleting(true)
    await Promise.all([...selected].map(id => api.deleteRun(id).catch(() => {})))
    setSelected(new Set())
    setDeleting(false)
    load()
  }

  async function cancelSelected() {
    const runningIds = filtered.filter(r => r.status === 'running' && selected.has(r.id)).map(r => r.id)
    if (!runningIds.length) return
    if (!window.confirm(`Cancel ${runningIds.length} running scan(s)?`)) return
    await Promise.all(runningIds.map(id => api.cancelRun(id).catch(() => {})))
    load()
  }

  const selectedRunning = filtered.filter(r => r.status === 'running' && selected.has(r.id)).length

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold text-[#e6edf3]">
          Runs <span className="text-[#8b949e] text-sm font-normal">({data.total})</span>
        </h1>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>+ New Run</button>
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <input
          className="input w-52"
          placeholder="Search target / workflow..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <div className="flex gap-1">
          {STATUSES.map(s => (
            <button
              key={s || 'all'}
              onClick={() => { setStatus(s); setPage(0) }}
              className={`btn text-xs ${status === s ? 'bg-[#58a6ff22] text-[#58a6ff]' : 'btn-ghost'}`}
            >
              {s || 'All'}
            </button>
          ))}
        </div>
      </div>

      {/* Bulk action bar */}
      {selected.size > 0 && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '8px 14px', borderRadius: 7,
          background: '#161b22', border: '1px solid #388bfd55',
          boxShadow: '0 0 0 1px #388bfd22',
        }}>
          <span style={{ fontSize: 12, color: '#58a6ff', fontWeight: 700 }}>
            {selected.size} selected
          </span>
          <div style={{ flex: 1 }} />
          {selectedRunning > 0 && (
            <button className="btn btn-danger" style={{ fontSize: 11 }} onClick={cancelSelected}>
              ■ Cancel {selectedRunning} running
            </button>
          )}
          <button
            className="btn btn-danger"
            style={{ fontSize: 11 }}
            onClick={deleteSelected}
            disabled={deleting}
          >
            {deleting ? 'Deleting…' : `🗑 Delete ${selected.size}`}
          </button>
          <button
            className="btn btn-ghost"
            style={{ fontSize: 11 }}
            onClick={() => setSelected(new Set())}
          >
            Clear
          </button>
        </div>
      )}

      {/* Table */}
      <div className="card overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-[#30363d]">
              {/* Select-all checkbox */}
              <th className="px-3 py-2.5 w-8">
                <input
                  type="checkbox"
                  checked={allChecked}
                  ref={el => { if (el) el.indeterminate = someChecked }}
                  onChange={toggleAll}
                  className="accent-[#58a6ff]"
                  style={{ cursor: 'pointer', width: 13, height: 13 }}
                />
              </th>
              {['Target', 'Workflow', 'Status', 'Started', 'Duration', 'Actions'].map(h => (
                <th key={h} className="px-4 py-2.5 text-left text-[#8b949e] text-[10px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-[#8b949e]">No runs found.</td></tr>
            )}
            {filtered.map(r => {
              const isSelected = selected.has(r.id)
              return (
                <tr
                  key={r.id}
                  className="border-b border-[#30363d] hover:bg-[#161b22] transition-colors group"
                  style={isSelected ? { background: '#0a1929' } : {}}
                >
                  {/* Row checkbox */}
                  <td className="px-3 py-2.5">
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => toggleOne(r.id)}
                      className="accent-[#58a6ff]"
                      style={{ cursor: 'pointer', width: 13, height: 13 }}
                    />
                  </td>
                  <td className="px-4 py-2.5 max-w-[220px] truncate">
                    <Link to={`/runs/${r.id}`} className="text-[#58a6ff] hover:underline font-mono">{r.target}</Link>
                  </td>
                  <td className="px-4 py-2.5 text-[#8b949e] max-w-[160px] truncate">{r.workflow}</td>
                  <td className="px-4 py-2.5">
                    <span className={`badge badge-${r.status}`}>{r.status}</span>
                  </td>
                  <td className="px-4 py-2.5 text-[#8b949e]" title={r.started_at || r.created_at}>
                    {timeAgo(r.started_at || r.created_at)}
                  </td>
                  <td className="px-4 py-2.5 text-[#8b949e] font-mono">
                    {r.status === 'running'
                      ? <span className="text-[#3fb950] animate-pulse">running…</span>
                      : formatDuration(durSecs(r))}
                  </td>
                  <td className="px-4 py-2.5 text-right opacity-0 group-hover:opacity-100 transition-opacity">
                    {r.status === 'running' && (
                      <button
                        className="btn btn-warning mr-2"
                        onClick={() => window.confirm(`Pause scan for ${r.target}?`) && api.pauseRun(r.id).then(load)}
                      >⏸ Pause</button>
                    )}
                    {r.status === 'running' && (
                      <button
                        className="btn btn-danger mr-2"
                        onClick={() => window.confirm(`Cancel scan for ${r.target}?`) && api.cancelRun(r.id).then(load)}
                      >■ Cancel</button>
                    )}
                    {(r.status === 'paused' || r.status === 'failed') && (
                      <button className="btn btn-success mr-2" onClick={() => api.resumeRun(r.id).then(load)}>
                        ▶ Resume
                      </button>
                    )}
                    <button
                      className="btn btn-ghost"
                      onClick={() => window.confirm(`Delete run for ${r.target}?`) && api.deleteRun(r.id).then(load)}
                    >Delete</button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {data.total > PAGE && (
        <div className="flex gap-2 justify-center">
          <button className="btn btn-ghost" disabled={page === 0} onClick={() => setPage(p => p - 1)}>← Prev</button>
          <span className="text-xs text-[#8b949e] self-center">{page + 1} / {Math.ceil(data.total / PAGE)}</span>
          <button className="btn btn-ghost" disabled={(page + 1) * PAGE >= data.total} onClick={() => setPage(p => p + 1)}>Next →</button>
        </div>
      )}

      {showModal && <NewRunModal onClose={() => setShowModal(false)} onCreated={() => { setShowModal(false); load() }} />}
    </div>
  )
}
