import React, { useState, useEffect, useCallback } from 'react'
import { api } from '../api.js'

const CATEGORY_ORDER = ['Internet Scanner', 'Subdomain Intel', 'Archive / Cert', 'Search & Dork']

// Keys that map directly to a workflow var (auto-injected at run time by tasks.py)
const KEY_VAR_MAP = {
  chaos:      { var: 'chaos_key',     workflows: ['k1nzr3con.yaml', '01-full-recon-pipeline.yaml'] },
}

const SUBFINDER_TOTAL = 21  // total providers supported

// Per-template key dependency map — drives the Template Sync panel
const TEMPLATE_DEPS = [
  {
    name: 'k1nzr3con.yaml',
    subfinder: true,
    autoVars: ['chaos_key'],   // vars auto-injected at run time
    note: null,
  },
  {
    name: '01-full-recon-pipeline.yaml',
    subfinder: true,
    autoVars: ['chaos_key'],
    note: null,
  },
  {
    name: '02-js-secrets-recon.yaml',
    subfinder: false,
    autoVars: [],
    note: 'no key integration — runs standalone',
  },
  {
    name: '03-param-discovery.yaml',
    subfinder: false,
    autoVars: [],
    note: 'session/token → use Auth section when creating run',
  },
]

export default function Keys() {
  const [keys, setKeys]       = useState([])
  const [editing, setEditing] = useState({})
  const [saving, setSaving]   = useState({})
  const [error, setError]     = useState(null)
  // provider → configured (derived from keys)
  const configuredSet = new Set(keys.filter(k => k.configured).map(k => k.provider))

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

  const configured = keys.filter(k => k.configured).length

  return (
    <div className="p-6 max-w-4xl">

      {/* Header */}
      <div className="mb-5 flex items-start justify-between">
        <div>
          <h1 className="text-[#e6edf3] text-xl font-semibold">Intelligence API Keys</h1>
          <p className="text-[#8b949e] text-sm mt-1">
            Keys are auto-injected into <strong className="text-[#e6edf3]">subfinder</strong> and
            {' '}<strong className="text-[#e6edf3]">workflow vars</strong> at run time — no manual copy-paste needed.
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

      {/* Template Sync — template-centric view */}
      <div style={{ marginBottom: 20, borderRadius: 8, border: '1px solid #21262d', overflow: 'hidden' }}>
        <div style={{
          padding: '7px 12px', background: '#0d1117',
          fontSize: 10, fontWeight: 700, color: '#484f58',
          textTransform: 'uppercase', letterSpacing: '0.08em',
          borderBottom: '1px solid #21262d',
        }}>
          Template Sync
        </div>
        {TEMPLATE_DEPS.map((tmpl, i) => {
          const isLast = i === TEMPLATE_DEPS.length - 1
          // Which auto-vars are active for this template
          const autoVarStatus = tmpl.autoVars.map(varName => {
            const entry = Object.entries(KEY_VAR_MAP).find(([, info]) => info.var === varName)
            const provider = entry?.[0]
            return { varName, active: provider ? configuredSet.has(provider) : false }
          })
          const hasAnyKey = tmpl.subfinder ? configured > 0 : autoVarStatus.some(v => v.active)

          return (
            <div key={tmpl.name} style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '8px 12px', background: '#161b22',
              borderBottom: isLast ? 'none' : '1px solid #21262d',
            }}>
              {/* Status dot */}
              <span style={{
                width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                background: hasAnyKey ? '#3fb950' : '#30363d',
              }} />

              {/* Template name */}
              <span style={{
                fontFamily: 'monospace', fontSize: 10, color: '#e6edf3',
                flexShrink: 0, minWidth: 220,
              }}>
                {tmpl.name}
              </span>

              {/* Key integration detail */}
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', flex: 1 }}>
                {tmpl.subfinder ? (
                  <>
                    <span style={{
                      fontSize: 9, padding: '1px 7px', borderRadius: 3,
                      background: configured > 0 ? '#0a1f0e' : '#0d1117',
                      border: `1px solid ${configured > 0 ? '#3fb95044' : '#21262d'}`,
                      color: configured > 0 ? '#3fb950' : '#484f58',
                    }}>
                      ⚙ subfinder {configured}/{SUBFINDER_TOTAL}
                    </span>
                    {autoVarStatus.map(({ varName, active }) => (
                      <span key={varName} style={{
                        fontSize: 9, padding: '1px 7px', borderRadius: 3,
                        fontFamily: 'monospace',
                        background: active ? '#0a192966' : '#0d1117',
                        border: `1px solid ${active ? '#58a6ff44' : '#21262d'}`,
                        color: active ? '#58a6ff' : '#484f58',
                      }}>
                        🔑 {varName} {active ? '✓' : '—'}
                      </span>
                    ))}
                  </>
                ) : (
                  <span style={{ fontSize: 9, color: '#484f58' }}>
                    ○ no key integration{tmpl.note ? ` — ${tmpl.note}` : ''}
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

      {CATEGORY_ORDER.map(cat => (
        <section key={cat} className="mb-7">
          <h2 className="text-[#8b949e] text-[10px] font-semibold uppercase tracking-widest mb-3 pb-2 border-b border-[#21262d]">
            {cat}
          </h2>
          <div className="space-y-1.5">
            {(byCategory[cat] || []).map(k => (
              <ProviderRow
                key={k.provider}
                k={k}
                keyVarInfo={KEY_VAR_MAP[k.provider] || null}
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
      ))}

      {keys.length === 0 && (
        <div className="text-center py-16 text-[#6e7681] text-sm">Loading providers…</div>
      )}
    </div>
  )
}

function ProviderRow({ k, keyVarInfo, editValue, saving, onEdit, onCancel, onChange, onSave, onDelete }) {
  const isEditing = editValue !== undefined

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

          {/* Subfinder badge — only for subfinder providers */}
          {k.meta?.subfinder !== false && (
            <span style={{
              fontSize: 8, padding: '1px 5px', borderRadius: 3,
              background: '#161b22', border: '1px solid #21262d', color: '#484f58',
            }}>subfinder</span>
          )}

          {/* Workflow var badge — for keys that inject into workflow vars */}
          {keyVarInfo && (
            <span style={{
              fontSize: 8, padding: '1px 6px', borderRadius: 3, fontFamily: 'monospace',
              background: k.configured ? '#0a192922' : '#161b22',
              border: `1px solid ${k.configured ? '#58a6ff55' : '#21262d'}`,
              color: k.configured ? '#58a6ff' : '#484f58',
            }}>
              🔑 → {keyVarInfo.var}
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
