import React, { useEffect, useState, useCallback, useRef } from 'react'
import { api } from '../api'

const CAT_LABEL = {
  gh_binary:    { text: 'binary',   cls: 'text-[var(--accent)] bg-[#58a6ff1a]' },
  pip:          { text: 'pip',      cls: 'text-[#d2a8ff] bg-[#d2a8ff1a]' },
  git:          { text: 'git',      cls: 'text-[var(--green)] bg-[#3fb9501a]' },
  rebuild_only: { text: 'rebuild',  cls: 'text-[var(--text-2)] bg-[#8b949e1a]' },
}

const STATUS_CFG = {
  ok:           { dot: 'bg-[var(--green)]',                    label: 'up to date'  },
  outdated:     { dot: 'bg-[#f0883e]',                    label: 'outdated'    },
  updating:     { dot: 'bg-[var(--accent)] animate-pulse',      label: 'updating…'   },
  failed:       { dot: 'bg-[var(--red)]',                    label: 'failed'      },
  check_failed: { dot: 'bg-[#f0883e] opacity-50',         label: 'check failed'},
  rebuild_only: { dot: 'bg-[var(--text-2)]',                    label: 'rebuild only'},
  unknown:      { dot: 'bg-[var(--text-2)]',                    label: 'unchecked'   },
}

function StatusDot({ status }) {
  const cfg = STATUS_CFG[status] || STATUS_CFG.unknown
  return (
    <span className="flex items-center gap-1.5">
      <span className={`inline-block w-2 h-2 rounded-full flex-shrink-0 ${cfg.dot}`} />
      <span className="text-[var(--text-2)]">{cfg.label}</span>
    </span>
  )
}

function CatBadge({ cat }) {
  const cfg = CAT_LABEL[cat] || { text: cat, cls: 'text-[var(--text-2)] bg-[#8b949e1a]' }
  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${cfg.cls}`}>
      {cfg.text}
    </span>
  )
}

function HealthPanel() {
  const [health, setHealth] = useState(null)

  useEffect(() => {
    let alive = true
    api.getHealth().then(h => { if (alive) setHealth(h) }).catch(() => {})
    return () => { alive = false }
  }, [])

  if (!health) return null

  const CHECKS = [
    ['redis',       'Redis',                      c => c.ok],
    ['worker',      'Worker',                     c => c.ok],
    ['beat',        'Beat',                       c => c.ok],
    ['disk',        `Disk ${health.checks.disk?.free_gb ?? '?'}GB free`, c => c.ok],
    ['resolvers',   'Resolvers',                  c => c.ok],
    ['webhook',     'Webhook',                    c => c.configured],
    ['stuck_runs',  'Stuck runs',                 c => c.ok],
  ]

  return (
    <div className="card p-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="section-title mr-1">System health</span>
        {CHECKS.map(([key, label, ok]) => {
          const c = health.checks[key] || {}
          const good = ok(c)
          return (
            <span key={key}
                  className="inline-flex items-center gap-1.5 text-[10px] font-mono px-2 py-1 rounded-full border"
                  style={{
                    color: good ? 'var(--green)' : 'var(--red)',
                    borderColor: good ? 'rgba(63,185,80,.35)' : 'rgba(248,81,73,.4)',
                    background: good ? 'rgba(63,185,80,.07)' : 'rgba(248,81,73,.08)',
                  }}
                  title={c.error || ''}>
              <span className="w-1.5 h-1.5 rounded-full" style={{ background: 'currentColor' }} />
              {label}
            </span>
          )
        })}
        {health.checks.stuck_runs?.count > 0 && (
          <span className="text-[10px]" style={{ color: 'var(--amber)' }}>
            {health.checks.stuck_runs.count} run(s) stuck &gt;13h
          </span>
        )}
      </div>
    </div>
  )
}

function VersionCell({ installed, latest, outdated }) {
  if (!installed) return <span className="text-[var(--text-3)]">—</span>
  return (
    <span className="font-mono text-xs">
      <span className={outdated ? 'text-[#f0883e]' : 'text-[var(--text)]'}>
        {installed}
      </span>
      {latest && outdated && (
        <span className="text-[var(--green)] ml-1">→ {latest}</span>
      )}
    </span>
  )
}

export default function Tools() {
  const [data, setData]         = useState(null)
  const [loading, setLoading]   = useState(true)
  const [checking, setChecking] = useState(false)
  const [updating, setUpdating] = useState(false)
  const [error, setError]       = useState(null)
  const [filter, setFilter]     = useState('all')  // all | outdated | updatable

  const load = useCallback(async () => {
    try {
      const d = await api.getTools()
      setData(d)
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // handleCheck's poll/timeout survive until the version check finishes —
  // clear them on unmount or they keep setState-ing a dead component.
  const checkPollRef = useRef(null)
  const checkTimerRef = useRef(null)
  useEffect(() => () => {
    if (checkPollRef.current) clearInterval(checkPollRef.current)
    if (checkTimerRef.current) clearTimeout(checkTimerRef.current)
  }, [])

  // Poll every 3s while any tool is updating or checking
  useEffect(() => {
    if (!data) return
    const busy =
      data.tools.some(t => t.status === 'updating') ||
      data.wordlists.some(w => w.status === 'updating')
    if (!busy) return
    const id = setInterval(load, 3000)
    return () => clearInterval(id)
  }, [data, load])

  const handleCheck = async () => {
    setChecking(true)
    // Snapshot last_checked_at before triggering so we know when the task finished
    const beforeTs = data?.tools.find(t => t.last_checked_at)?.last_checked_at ?? null
    try {
      await api.checkToolVersions()
    } catch (e) {
      setError(e.message)
      setChecking(false)
      return
    }
    // Poll every 2s until last_checked_at advances (task completed)
    let done = false
    if (checkPollRef.current) clearInterval(checkPollRef.current)
    if (checkTimerRef.current) clearTimeout(checkTimerRef.current)
    checkTimerRef.current = setTimeout(() => { done = true; setChecking(false) }, 120_000)
    checkPollRef.current = setInterval(async () => {
      if (done) { clearInterval(checkPollRef.current); checkPollRef.current = null; return }
      try {
        const fresh = await api.getTools()
        const afterTs = fresh.tools.find(t => t.last_checked_at)?.last_checked_at ?? null
        if (afterTs && afterTs !== beforeTs) {
          clearInterval(checkPollRef.current)
          clearTimeout(checkTimerRef.current)
          checkPollRef.current = null
          checkTimerRef.current = null
          setData(fresh)
          setChecking(false)
        }
      } catch (_) {}
    }, 2000)
  }

  const handleUpdateAll = async () => {
    setUpdating(true)
    try {
      // Only dispatch tools that are confirmed outdated (not check_failed, not already ok).
      // Sending an empty array is safe: the backend only triggers "update all" when the
      // 'tools' key is absent entirely, not when it's an empty list.
      const outdatedNames = (data?.tools ?? [])
        .filter(t => t.outdated && t.updatable)
        .map(t => t.name)
      if (outdatedNames.length === 0) return
      await api.updateTools({ tools: outdatedNames })
      // Give Celery time to mark tasks as "updating" before refreshing
      await new Promise(r => setTimeout(r, 600))
      await load()
    } catch (e) {
      setError(e.message)
    } finally {
      setUpdating(false)
    }
  }

  const handleUpdateOne = async (name, kind) => {
    try {
      if (kind === 'wordlist') {
        await api.updateTools({ wordlists: [name] })
      } else {
        await api.updateTools({ tools: [name] })
      }
      // Give Celery ~600ms to pick up the task and set status="updating" in the DB
      // before we load, so the polling useEffect sees "busy" and keeps refreshing.
      await new Promise(r => setTimeout(r, 600))
      await load()
    } catch (e) {
      setError(e.message)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-2)] text-sm">
        Loading tools…
      </div>
    )
  }

  if (error && !data) {
    return (
      <div className="p-6 text-[var(--red)] text-sm">Error: {error}</div>
    )
  }

  const { tools = [], wordlists = [], outdated_count = 0, check_failed_count = 0 } = data || {}

  const visibleTools = tools.filter(t => {
    if (filter === 'outdated') return t.outdated
    if (filter === 'updatable') return t.updatable
    return true
  })

  const anyUpdating = tools.some(t => t.status === 'updating') ||
                      wordlists.some(w => w.status === 'updating')

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[var(--text)] font-semibold text-lg">Tools</h1>
          <p className="text-[var(--text-2)] text-xs mt-0.5">
            {tools.length} tools · {wordlists.length} wordlists
            {outdated_count > 0 && (
              <span className="ml-2 text-[#f0883e]">· {outdated_count} outdated</span>
            )}
            {check_failed_count > 0 && (
              <span className="ml-2 text-[#f0883e] opacity-60">· {check_failed_count} check failed</span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleCheck}
            disabled={checking || anyUpdating}
            className="px-3 py-1.5 rounded text-xs border border-[var(--border)] text-[var(--text-2)]
                       hover:text-[var(--text)] hover:border-[var(--text-3)] transition-colors
                       disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {checking ? 'Checking…' : 'Check Updates'}
          </button>
          <button
            onClick={handleUpdateAll}
            disabled={updating || anyUpdating || outdated_count === 0}
            className="px-3 py-1.5 rounded text-xs bg-[#238636] text-white
                       hover:bg-[#2ea043] transition-colors
                       disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {anyUpdating ? 'Updating…' : outdated_count > 0 ? `Update ${outdated_count} outdated` : 'Up to date'}
          </button>
        </div>
      </div>

      {/* System health */}
      <HealthPanel />

      {/* Warning banner */}
      <div className="rounded border border-[#f0883e33] bg-[#f0883e0d] px-4 py-2.5 text-xs text-[#f0883e]">
        ⚠ Updates are applied in-place to the running container and will be lost after restart.
        Run <code className="font-mono bg-[var(--surface)] px-1 py-0.5 rounded">docker compose build</code> to persist changes.
      </div>

      {error && (
        <div className="rounded border border-[#f8514933] bg-[#f851490d] px-4 py-2 text-xs text-[var(--red)]">
          {error}
        </div>
      )}

      {/* Filter tabs */}
      <div className="flex gap-1">
        {[['all', 'All'], ['outdated', 'Outdated'], ['updatable', 'Updatable']].map(([v, label]) => (
          <button
            key={v}
            onClick={() => setFilter(v)}
            className={`px-3 py-1 rounded text-xs transition-colors ${
              filter === v
                ? 'bg-[#58a6ff1a] text-[var(--accent)]'
                : 'text-[var(--text-2)] hover:text-[var(--text)]'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Tools table */}
      <div className="rounded border border-[var(--border)] overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-[var(--border)] bg-[var(--surface)]">
              <th className="px-4 py-2.5 text-left text-[var(--text-2)] font-medium">Tool</th>
              <th className="px-4 py-2.5 text-left text-[var(--text-2)] font-medium">Type</th>
              <th className="px-4 py-2.5 text-left text-[var(--text-2)] font-medium">Version</th>
              <th className="px-4 py-2.5 text-left text-[var(--text-2)] font-medium">Status</th>
              <th className="px-4 py-2.5 text-right text-[var(--text-2)] font-medium">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--surface-2)]">
            {visibleTools.map(tool => (
              <tr key={tool.name} className="hover:bg-[var(--surface-2)] transition-colors">
                <td className="px-4 py-2.5">
                  <div className="font-mono text-[var(--text)]">{tool.display}</div>
                  <div className="text-[var(--text-2)] text-[10px] mt-0.5 truncate max-w-xs">{tool.desc}</div>
                </td>
                <td className="px-4 py-2.5">
                  <CatBadge cat={tool.cat} />
                </td>
                <td className="px-4 py-2.5">
                  <VersionCell
                    installed={tool.installed}
                    latest={tool.latest}
                    outdated={tool.outdated}
                  />
                </td>
                <td className="px-4 py-2.5">
                  <StatusDot status={tool.status} />
                  {tool.error_msg && (
                    <div className="text-[var(--red)] text-[10px] mt-0.5 truncate max-w-xs" title={tool.error_msg}>
                      {tool.error_msg}
                    </div>
                  )}
                </td>
                <td className="px-4 py-2.5 text-right">
                  {tool.updatable && tool.status !== 'updating' ? (
                    <button
                      onClick={() => handleUpdateOne(tool.name, 'tool')}
                      disabled={anyUpdating}
                      className="px-2 py-1 rounded text-[10px] border border-[var(--border)]
                                 text-[var(--text-2)] hover:text-[var(--text)] hover:border-[var(--text-3)]
                                 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      {tool.outdated ? '↑ Update' : '↺ Reinstall'}
                    </button>
                  ) : tool.status === 'updating' ? (
                    <span className="text-[var(--text-2)] text-[10px]">updating…</span>
                  ) : (
                    <span className="text-[var(--text-3)] text-[10px]">rebuild only</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Wordlists table */}
      <div>
        <h2 className="text-[var(--text-2)] text-xs font-medium mb-3 uppercase tracking-wider">Wordlists</h2>
        <div className="rounded border border-[var(--border)] overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[var(--border)] bg-[var(--surface)]">
                <th className="px-4 py-2.5 text-left text-[var(--text-2)] font-medium">Wordlist</th>
                <th className="px-4 py-2.5 text-left text-[var(--text-2)] font-medium">File</th>
                <th className="px-4 py-2.5 text-left text-[var(--text-2)] font-medium">Size</th>
                <th className="px-4 py-2.5 text-left text-[var(--text-2)] font-medium">Status</th>
                <th className="px-4 py-2.5 text-right text-[var(--text-2)] font-medium">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--surface-2)]">
              {wordlists.map(wl => (
                <tr key={wl.name} className="hover:bg-[var(--surface-2)] transition-colors">
                  <td className="px-4 py-2.5 text-[var(--text)] font-mono">{wl.display}</td>
                  <td className="px-4 py-2.5 text-[var(--text-2)] font-mono">{wl.file}</td>
                  <td className="px-4 py-2.5 text-[var(--text)]">
                    {wl.installed || <span className="text-[var(--text-3)]">—</span>}
                  </td>
                  <td className="px-4 py-2.5">
                    <StatusDot status={wl.status} />
                    {wl.error_msg && (
                      <div className="text-[var(--red)] text-[10px] mt-0.5" title={wl.error_msg}>
                        {wl.error_msg}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    {wl.status !== 'updating' ? (
                      <button
                        onClick={() => handleUpdateOne(wl.name, 'wordlist')}
                        disabled={anyUpdating}
                        className="px-2 py-1 rounded text-[10px] border border-[var(--border)]
                                   text-[var(--text-2)] hover:text-[var(--text)] hover:border-[var(--text-3)]
                                   transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                      >
                        ↺ Re-download
                      </button>
                    ) : (
                      <span className="text-[var(--text-2)] text-[10px]">updating…</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Last checked */}
      {tools[0]?.last_checked_at && (
        <p className="text-[var(--text-3)] text-[10px]">
          Last checked: {new Date(tools[0].last_checked_at).toLocaleString()}
        </p>
      )}
    </div>
  )
}
