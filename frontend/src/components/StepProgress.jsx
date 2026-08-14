import React, { useState } from 'react'
import { formatDuration } from '../utils.js'

const STATUS_ICON = {
  pending:  { icon: '○', cls: 'text-[var(--text-3)]' },
  running:  { icon: '◉', cls: 'text-[var(--accent)] animate-pulse' },
  ok:       { icon: '✓', cls: 'text-[var(--green)]' },
  skipped:  { icon: '–', cls: 'text-[var(--text-2)]' },
  failed:   { icon: '✗', cls: 'text-[var(--red)]' },
  paused:   { icon: '', cls: 'text-[var(--amber)]' },
}

// Make raw step IDs readable: gobuster_dns → "gobuster dns"
function fmtId(id) {
  return id.replace(/_/g, ' ')
}

/* Render a step's command(s): plain `cmd` or fanout list [{id, cmd}] */
function CmdBlock({ step }) {
  const entries = Array.isArray(step.fanout)
    ? step.fanout.map(f => ({ label: `${step.id}.${f.id}`, cmd: f.cmd }))
    : step.cmd ? [{ label: step.id, cmd: step.cmd }] : []
  if (entries.length === 0) return (
    <p className="text-[10px] italic" style={{ color: 'var(--text-3)' }}>no command recorded</p>
  )
  return (
    <div className="space-y-1.5">
      {entries.map(e => (
        <div key={e.label}>
          <p className="text-[9px] font-bold uppercase tracking-wider mb-0.5" style={{ color: 'var(--text-3)' }}>
            {e.label}
          </p>
          <pre
            className="text-[10px] font-mono leading-relaxed p-2 rounded overflow-x-auto whitespace-pre-wrap break-all"
            style={{ background: 'var(--bg-soft)', color: 'var(--text-2)', border: '1px solid var(--border)' }}
          >
            {e.cmd}
          </pre>
        </div>
      ))}
    </div>
  )
}

export default function StepProgress({ steps, running }) {
  const [expanded, setExpanded] = useState(null)
  if (!steps || steps.length === 0) return null

  const done    = steps.filter(s => s.status === 'ok').length
  const failed  = steps.filter(s => s.status === 'failed').length
  const skipped = steps.filter(s => s.status === 'skipped').length
  const total   = steps.length
  const pct     = Math.round((done / total) * 100)
  const running_steps = steps.filter(s => s.status === 'running')
  const expandedStep  = steps.find(s => s.id === expanded) || null

  // Progress bar: only colour red if any *non-optional* steps failed
  const barColor = failed > 0 ? '#f85149' : '#3fb950'

  return (
    <div className="border-b border-[var(--border)] px-6 py-3">
      {/* Summary line */}
      <div className="flex items-center gap-3 mb-2.5">
        <span className="text-xs text-[var(--text-2)] tabular-nums">
          {done}/{total} steps
        </span>
        {skipped > 0 && (
          <span className="text-[10px] text-[var(--text-3)]">{skipped} skipped</span>
        )}
        {failed > 0 && (
          <span className="text-xs text-[var(--red)]">{failed} failed</span>
        )}
        {running_steps.map(s => (
          <button
            key={s.id}
            onClick={() => setExpanded(expanded === s.id ? null : s.id)}
            className="text-xs text-[var(--accent)] animate-pulse hover:underline cursor-pointer"
            title="Click to view this step's command"
          >
            ◉ {fmtId(s.id)}
            {s.duration_ms != null && (
              <span className="text-[var(--text-3)] ml-1">{formatDuration(Math.round(s.duration_ms / 1000))}</span>
            )}
          </button>
        ))}
        {!running && done > 0 && done === total - skipped && failed === 0 && (
          <span className="text-xs text-[var(--green)]">✓ Complete</span>
        )}
        <div className="flex-1 h-1.5 bg-[var(--surface-2)] rounded-full overflow-hidden ml-2">
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{ width: `${pct}%`, background: barColor }}
          />
        </div>
        <span className="text-[10px] text-[var(--text-2)] tabular-nums">{pct}%</span>
      </div>

      {/* Live command of the currently running step(s) */}
      {running_steps.length > 0 && (
        <div className="mb-2.5 fade-in">
          {running_steps.map(s => (
            <div key={s.id} className="flex items-start gap-2 px-2.5 py-1.5 rounded-md"
                 style={{ background: 'rgba(88,166,255,.06)', border: '1px solid rgba(88,166,255,.25)' }}>
              <span className="text-[10px] font-mono mt-0.5 animate-pulse" style={{ color: 'var(--accent)' }}>▶</span>
              <div className="min-w-0 flex-1">
                <p className="text-[10px] font-semibold mb-0.5" style={{ color: 'var(--accent)' }}>
                  {s.name || fmtId(s.id)}
                </p>
                <pre
                  className="text-[10px] font-mono leading-snug overflow-hidden whitespace-pre-wrap break-all"
                  style={{ color: 'var(--text-2)', maxHeight: 54 }}
                >
                  {Array.isArray(s.fanout)
                    ? s.fanout.map(f => `.${f.id}: ${f.cmd}`).join('\n')
                    : (s.cmd || '…')}
                </pre>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Step chips */}
      <div className="flex flex-wrap gap-1.5">
        {steps.map(step => {
          const { icon, cls } = STATUS_ICON[step.status] || STATUS_ICON.pending
          const dur = step.duration_ms != null ? formatDuration(Math.round(step.duration_ms / 1000)) : null
          const isExp = expanded === step.id
          return (
            <button
              key={step.id}
              onClick={() => setExpanded(isExp ? null : step.id)}
              title={`${step.id} · ${step.status}${dur ? ` · ${dur}` : ''} — click to view command`}
              className={`flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border transition-colors cursor-pointer
                ${isExp               ? 'border-[#58a6ffaa] bg-[#58a6ff1a]'
                  : step.status === 'running' ? 'border-[#58a6ff55] bg-[#58a6ff0d]'
                  : step.status === 'failed'  ? 'border-[#f8514955] bg-[#f851490d]'
                  : step.status === 'ok'      ? 'border-[#3fb95033] bg-[#3fb9500a]'
                  : step.status === 'paused'  ? 'border-[#f0b42955] bg-[#f0b4290d]'
                  : 'border-[var(--surface-2)] bg-transparent hover:border-[var(--border-2)]'}`}
            >
              <span className={`font-mono text-[11px] ${cls}`}>{icon}</span>
              <span className={step.status === 'pending' || step.status === 'skipped' ? 'text-[var(--text-3)]' : 'text-[var(--text-2)]'}>
                {fmtId(step.id)}
              </span>
              {dur && step.status === 'ok' && (
                <span className="text-[var(--text-3)] ml-0.5">{dur}</span>
              )}
            </button>
          )
        })}
      </div>

      {/* Expanded command panel for the selected step */}
      {expandedStep && (
        <div className="mt-2.5 p-3 rounded-lg fade-in"
             style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between mb-2">
            <p className="text-[11px] font-semibold" style={{ color: 'var(--text)' }}>
              {expandedStep.name || fmtId(expandedStep.id)}
              <span className="ml-2 text-[9px] font-mono uppercase" style={{ color: 'var(--text-3)' }}>
                {expandedStep.status}
              </span>
            </p>
            <button className="btn btn-ghost" style={{ fontSize: 10 }} onClick={() => setExpanded(null)}>
              ✕ close
            </button>
          </div>
          <CmdBlock step={expandedStep} />
        </div>
      )}
    </div>
  )
}
