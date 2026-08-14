import React from 'react'
import { formatDuration } from '../utils.js'

const STATUS_ICON = {
  pending:  { icon: '○', cls: 'text-[var(--text-3)]' },
  running:  { icon: '◉', cls: 'text-[var(--accent)] animate-pulse' },
  ok:       { icon: '✓', cls: 'text-[var(--green)]' },
  skipped:  { icon: '–', cls: 'text-[var(--text-2)]' },
  failed:   { icon: '✗', cls: 'text-[var(--red)]' },
  paused:   { icon: '⏸', cls: 'text-[var(--amber)]' },
}

// Make raw step IDs readable: gobuster_dns → "gobuster dns"
function fmtId(id) {
  return id.replace(/_/g, ' ')
}

export default function StepProgress({ steps, running }) {
  if (!steps || steps.length === 0) return null

  const done    = steps.filter(s => s.status === 'ok').length
  const failed  = steps.filter(s => s.status === 'failed').length
  const skipped = steps.filter(s => s.status === 'skipped').length
  const total   = steps.length
  const pct     = Math.round((done / total) * 100)
  const running_steps = steps.filter(s => s.status === 'running')

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
          <span key={s.id} className="text-xs text-[var(--accent)] animate-pulse">
            ◉ {fmtId(s.id)}
            {s.duration_ms != null && (
              <span className="text-[var(--text-3)] ml-1">{formatDuration(Math.round(s.duration_ms / 1000))}</span>
            )}
          </span>
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

      {/* Step chips */}
      <div className="flex flex-wrap gap-1.5">
        {steps.map(step => {
          const { icon, cls } = STATUS_ICON[step.status] || STATUS_ICON.pending
          const dur = step.duration_ms != null ? formatDuration(Math.round(step.duration_ms / 1000)) : null
          return (
            <div
              key={step.id}
              title={`${step.id} · ${step.status}${dur ? ` · ${dur}` : ''}`}
              className={`flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border transition-colors
                ${step.status === 'running' ? 'border-[#58a6ff55] bg-[#58a6ff0d]'
                  : step.status === 'failed'  ? 'border-[#f8514955] bg-[#f851490d]'
                  : step.status === 'ok'      ? 'border-[#3fb95033] bg-[#3fb9500a]'
                  : step.status === 'paused'  ? 'border-[#f0b42955] bg-[#f0b4290d]'
                  : 'border-[var(--surface-2)] bg-transparent'}`}
            >
              <span className={`font-mono text-[11px] ${cls}`}>{icon}</span>
              <span className={step.status === 'pending' || step.status === 'skipped' ? 'text-[var(--text-3)]' : 'text-[var(--text-2)]'}>
                {fmtId(step.id)}
              </span>
              {dur && step.status === 'ok' && (
                <span className="text-[var(--text-3)] ml-0.5">{dur}</span>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
