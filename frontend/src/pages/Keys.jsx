import React, { useState, useEffect, useCallback } from 'react'
import { api } from '../api.js'

const CATEGORY_ORDER = [
  'Internet Scanner',
  'Subdomain Intel',
  'Archive / Cert',
  'Search & Dork',
  'AI Assistant',
]

// Workflows that receive full key injection at run time via _build_key_env()
// keysInjected: true  → workflow has explicit key-guarded steps (chaos/securitytrails/shodan/etc.)
// keysInjected: false → no explicit key steps, but env vars ARE still injected by tasks.py
const TEMPLATE_DEPS = [
  {
    name: 'k1nzr3con.yaml',
    keysInjected: true,
    note: null,
  },
  {
    name: '01-full-recon-pipeline.yaml',
    keysInjected: true,
    note: null,
  },
  {
    name: 'workflow-all.yaml',
    keysInjected: true,
    note: null,
  },
  {
    name: '02-js-secrets-recon.yaml',
    keysInjected: false,
    note: 'env vars injected — no key-specific steps (gau/waymore pick up URLSCAN_API_KEY automatically)',
  },
  {
    name: '03-param-discovery.yaml',
    keysInjected: false,
    note: 'env vars injected — use Auth section for session/token headers when creating run',
  },
]

export default function Keys() {
  const [keys, setKeys]       = useState([])
  const [editing, setEditing] = useState({})
  const [saving, setSaving]   = useState({})
  const [error, setError]     = useState(null)

  const configured    = keys.filter(k => k.configured).length
  const configuredSet = new Set(keys.filter(k => k.configured).map(k => k.provider))

  // Counts per category (for Template Sync badge)
  const subfinder_configured = keys.filter(k => k.configured && k.meta?.subfinder !== false).length
  const subfinder_total      = keys.filter(k => k.meta?.subfinder !== false).length

  const load = useCallback(() => {
    api.getKeys().then(setKeys).catch(e => setError(e.message))
  }, [])

  useEffect(() => { load() }, [load])

  function startEdit(provider) {
    setEditing(prev => ({ ...prev, [provider]: '' }))
  }
  function cancelEdit(provider) {
    setEditing(prev => { const n = { ...prev }; delete n[provider]; return n })
  }
  async function save(provider) {
    const value = (editing[provider] || '').trim()
    if (!value) return
    setSaving(prev => ({ ...prev, [provider]: true }))
    try {
      await api.setKey(provider, value)
      cancelEdit(provider)
      load()
    } catch (e) { setError(e.message) }
    finally { setSaving(prev => { const n = { ...prev }; delete n[provider]; return n }) }
  }
  async function del(provider) {
    try { await api.deleteKey(provider); load() }
    catch (e) { setError(e.message) }
  }

  const byCategory = CATEGORY_ORDER.reduce((acc, cat) => {
    acc[cat] = keys.filter(k => k.meta?.category === cat)
    return acc
  }, {})

  return (
    <div className="p-6 max-w-4xl">

      {/* Header */}
      <div className="mb-5 flex items-start justify-between">
        <div>
          <h1 className="text-[#e6edf3] text-xl font-semibold">Intelligence API Keys</h1>
          <p className="text-[#8b949e] text-sm mt-1">
            Keys saved here are auto-injected as <strong className="text-[#e6edf3]">$ENV_VARs</strong> and into{' '}
            <strong className="text-[#e6edf3]">subfinder</strong> on every workflow run — no manual copy-paste needed.
          </p>
        </div>
        <div className="text-right flex-shrink-0 ml-4">
          <span className="text-2xl font-bold tabular-nums" style={{ color: configured > 0 ? '#3fb950' : '#6e7681' }}>
            {configured}
          </span>
          <span className="text-[#6e7681] text-sm"> / {keys.length}</span>
          <p className="text-[#6e7681] text-xs">configured</p>
        </div>
      </div>

      {/* Template Sync panel */}
      <div style={{ marginBottom: 20, borderRadius: 8, border: '1px solid #21262d', overflow: 'hidden' }}>
        <div style={{
          padding: '7px 12px', background: '#0d1117',
          fontSize: 10, fontWeight: 700, color: '#484f58',
          textTransform: 'uppercase', letterSpacing: '0.08em',
          borderBottom: '1px solid #21262d',
        }}>
          Workflow Key Sync — all configured keys auto-injected at run time
        </div>
        {TEMPLATE_DEPS.map((tmpl, i) => {
          const isLast   = i === TEMPLATE_DEPS.length - 1
          const active   = tmpl.keysInjected && configured > 0

          return (
            <div key={tmpl.name} style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '8px 12px', background: '#161b22',
              borderBottom: isLast ? 'none' : '1px solid #21262d',
            }}>
              {/* Status dot */}
              <span style={{
                width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                background: active ? '#3fb950' : '#30363d',
              }} />

              {/* Template name */}
              <span style={{
                fontFamily: 'monospace', fontSize: 10, color: '#e6edf3',
                flexShrink: 0, minWidth: 220,
              }}>
                {tmpl.name}
              </span>

              {/* Integration detail */}
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', flex: 1 }}>
                {tmpl.keysInjected ? (
                  <>
                    {/* Env vars badge */}
                    <span style={{
                      fontSize: 9, padding: '1px 7px', borderRadius: 3,
                      background: configured > 0 ? '#0a1f0e' : '#0d1117',
                      border: `1px solid ${configured > 0 ? '#3fb95044' : '#21262d'}`,
                      color: configured > 0 ? '#3fb950' : '#484f58',
                    }}>
                      ⚡ {configured} $ENV_VAR{configured !== 1 ? 's' : ''} injected
                    </span>
                    {/* Subfinder badge */}
                    <span style={{
                      fontSize: 9, padding: '1px 7px', borderRadius: 3,
                      background: subfinder_configured > 0 ? '#0a192966' : '#0d1117',
                      border: `1px solid ${subfinder_configured > 0 ? '#58a6ff44' : '#21262d'}`,
                      color: subfinder_configured > 0 ? '#58a6ff' : '#484f58',
                    }}>
                      ⚙ subfinder {subfinder_configured}/{subfinder_total}
                    </span>
                  </>
                ) : (
                  <span style={{ fontSize: 9, color: '#484f58' }}>
                    ○ {tmpl.note}
                  </span>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {error && (
        <div className="mb-4 px-4 py-2 rounded bg-[#f851491a] border border-[#f85149] text-[#f85149] text-sm flex items-center gap-3">
          <span className="flex-1">{error}</span>
          <button className="underline text-xs opacity-75 hover:opacity-100" onClick={() => setError(null)}>dismiss</button>
        </div>
      )}

      {CATEGORY_ORDER.map(cat => {
        const rows = byCategory[cat] || []
        if (rows.length === 0) return null
        return (
          <section key={cat} className="mb-7">
            <h2 className="text-[#8b949e] text-[10px] font-semibold uppercase tracking-widest mb-3 pb-2 border-b border-[#21262d]">
              {cat}
            </h2>
            <div className="space-y-1.5">
              {rows.map(k => (
                <ProviderRow
                  key={k.provider}
                  k={k}
                  editValue={editing[k.provider]}
                  saving={!!saving[k.provider]}
                  onEdit={() => startEdit(k.provider)}
                  onCancel={() => cancelEdit(k.provider)}
                  onChange={v => setEditing(prev => ({ ...prev, [k.provider]: v }))}
                  onSave={() => save(k.provider)}
                  onDelete={() => del(k.provider)}
                />
              ))}
            </div>
          </section>
        )
      })}

      {keys.length === 0 && (
        <div className="text-center py-16 text-[#6e7681] text-sm">Loading providers…</div>
      )}
    </div>
  )
}

function ProviderRow({ k, editValue, saving, onEdit, onCancel, onChange, onSave, onDelete }) {
  const isEditing = editValue !== undefined
  const envVar    = k.meta?.env_var   // e.g. "SHODAN_API_KEY"

  return (
    <div className={`flex items-center gap-3 px-4 py-3 rounded-lg border transition-colors ${
      isEditing
        ? 'border-[#388bfd] bg-[#161b22]'
        : 'border-[#21262d] bg-[#161b22] hover:border-[#30363d]'
    }`}>
      {/* Status dot */}
      <span className={`w-2 h-2 rounded-full flex-shrink-0 transition-colors ${
        k.configured ? 'bg-[#3fb950]' : 'bg-[#30363d]'
      }`} />

      {/* Provider info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[#e6edf3] text-sm font-medium">{k.meta?.name || k.provider}</span>
          <span className="text-[#484f58] text-xs">{k.meta?.url}</span>

          {/* Subfinder badge */}
          {k.meta?.subfinder !== false && (
            <span style={{
              fontSize: 8, padding: '1px 5px', borderRadius: 3,
              background: '#161b22', border: '1px solid #21262d', color: '#484f58',
            }}>subfinder</span>
          )}

          {/* Env var badge — shown for EVERY provider */}
          {envVar && (
            <span style={{
              fontSize: 8, padding: '1px 6px', borderRadius: 3, fontFamily: 'monospace',
              background: k.configured ? '#0a1f0e22' : '#0d1117',
              border: `1px solid ${k.configured ? '#3fb95044' : '#21262d'}`,
              color: k.configured ? '#3fb950' : '#484f58',
            }}>
              ${envVar}
            </span>
          )}

          {/* Special: censys has two env vars */}
          {k.provider === 'censys' && k.configured && (
            <span style={{
              fontSize: 8, padding: '1px 6px', borderRadius: 3, fontFamily: 'monospace',
              background: '#0a1f0e22', border: '1px solid #3fb95044', color: '#3fb950',
            }}>
              $CENSYS_API_SECRET
            </span>
          )}
        </div>

        {!isEditing && k.configured && (
          <div className="text-[#8b949e] text-xs font-mono mt-0.5 tracking-wider">{k.masked}</div>
        )}
        {!isEditing && !k.configured && (
          <div className="text-[#484f58] text-xs mt-0.5 truncate">{k.meta?.hint}</div>
        )}

        {isEditing && (
          <div className="flex items-center gap-2 mt-2">
            <input
              className="flex-1 min-w-0 bg-[#0d1117] border border-[#30363d] rounded px-2.5 py-1.5 text-xs text-[#e6edf3] font-mono focus:outline-none focus:border-[#388bfd] placeholder-[#484f58]"
              placeholder={k.meta?.hint || 'Paste API key…'}
              value={editValue}
              onChange={e => onChange(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') onSave(); if (e.key === 'Escape') onCancel() }}
              autoFocus
            />
            <button
              className="px-3 py-1.5 text-xs rounded bg-[#238636] hover:bg-[#2ea043] text-white disabled:opacity-40 transition-colors flex-shrink-0"
              onClick={onSave}
              disabled={saving || !editValue?.trim()}
            >
              {saving ? '…' : 'Save'}
            </button>
            <button
              className="px-3 py-1.5 text-xs rounded border border-[#30363d] text-[#8b949e] hover:text-[#e6edf3] hover:border-[#6e7681] transition-colors flex-shrink-0"
              onClick={onCancel}
            >
              Cancel
            </button>
          </div>
        )}
      </div>

      {/* Actions */}
      {!isEditing && (
        <div className="flex items-center gap-1 flex-shrink-0">
          <button
            className="px-3 py-1 text-xs rounded border border-[#30363d] text-[#8b949e] hover:text-[#e6edf3] hover:border-[#6e7681] transition-colors"
            onClick={onEdit}
          >
            {k.configured ? 'Update' : 'Add'}
          </button>
          {k.configured && (
            <button
              className="w-7 h-7 flex items-center justify-center text-xs rounded text-[#484f58] hover:text-[#f85149] hover:bg-[#f851491a] transition-colors"
              onClick={onDelete}
              title="Remove key"
            >✕</button>
          )}
        </div>
      )}
    </div>
  )
}
