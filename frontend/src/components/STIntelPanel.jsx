import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

/* SecurityTrails intel viewer — everything `securitytrails_fetch.py --mode all`
   collected for the run's target: subdomains, DNS records, WHOIS (+history),
   SSL certs, associated domains, NS/MX pivot leads. */

const FILE_META = {
  'p_securitytrails.txt':   { label: 'Subdomains',        hint: 'all subdomains — feeds the recon pipeline' },
  'st_subdomains.txt':      { label: 'Subdomains (raw)',  hint: 'raw ST subdomain list' },
  'st_dns_records.txt':     { label: 'DNS Records',       hint: 'NS/MX/A/AAAA/TXT — current + historical' },
  'st_domain_info.json':    { label: 'Domain Info',       hint: 'current domain snapshot' },
  'st_whois.json':          { label: 'WHOIS',             hint: 'current WHOIS record' },
  'st_whois_history.json':  { label: 'WHOIS History',     hint: 'every WHOIS change ST observed' },
  'st_ssl.json':            { label: 'SSL Certificates',  hint: 'TLS certs observed for the domain' },
  'st_associated.txt':      { label: 'Associated',        hint: 'ST-linked domains (same company/infra) — intel leads' },
  'st_pivot_domains.txt':   { label: 'NS/MX Pivot',       hint: 'domains sharing NS/MX — intel leads, NOT auto-scanned' },
}

export default function STIntelPanel({ runId }) {
  const [files, setFiles] = useState([])
  const [selected, setSelected] = useState(null)
  const [content, setContent] = useState(null)
  const [loading, setLoading] = useState(false)
  const [checked, setChecked] = useState(false)

  useEffect(() => {
    api.getFiles(runId)
      .then(list => {
        const intel = (list || []).filter(f =>
          f.name.startsWith('st_') || f.name === 'p_securitytrails.txt')
        // dedupe p_securitytrails vs st_subdomains (same data)
        const seen = new Set()
        const uniq = intel.filter(f => {
          const key = f.name === 'st_subdomains.txt' ? 'subs' : f.name
          if (seen.has(key)) return false
          seen.add(key)
          return true
        })
        setFiles(uniq)
        if (uniq.length > 0) setSelected(uniq[0].path)
        setChecked(true)
      })
      .catch(() => setChecked(true))
  }, [runId])

  useEffect(() => {
    if (!selected) return
    setLoading(true)
    api.getFileContent(runId, selected)
      .then(text => {
        if (selected.endsWith('.json')) {
          try {
            setContent(JSON.stringify(JSON.parse(text), null, 2))
          } catch {
            setContent(text)
          }
        } else {
          setContent(text)
        }
      })
      .catch(e => setContent(`(load failed: ${e.message})`))
      .finally(() => setLoading(false))
  }, [selected, runId])

  if (!checked) return <div className="p-6 text-xs" style={{ color: 'var(--text-3)' }}>Loading…</div>

  if (files.length === 0) {
    return (
      <div className="p-8 text-center">
        <p className="text-sm mb-1" style={{ color: 'var(--text-2)' }}>No SecurityTrails intel for this run.</p>
        <p className="text-[11px]" style={{ color: 'var(--text-3)' }}>
          Set SECURITYTRAILS_KEY in /opt/k1nzr3c0n/.env and run the 01 pipeline
          (step p_securitytrails fetches everything with --mode all).
        </p>
      </div>
    )
  }

  const sel = files.find(f => f.path === selected)
  const meta = sel ? FILE_META[sel.name] : null
  const lineCount = content ? content.split('\n').filter(Boolean).length : 0

  return (
    <div className="flex gap-0" style={{ minHeight: 380 }}>
      {/* File list */}
      <div className="w-48 flex-shrink-0 border-r py-2" style={{ borderColor: 'var(--border)' }}>
        {files.map(f => {
          const m = FILE_META[f.name]
          const active = f.path === selected
          return (
            <button
              key={f.path}
              onClick={() => setSelected(f.path)}
              className="w-full text-left px-3 py-2 transition-colors"
              style={{
                background: active ? 'rgba(88,166,255,.10)' : 'transparent',
                borderLeft: active ? '2px solid var(--accent)' : '2px solid transparent',
              }}
            >
              <p className="text-[11px] font-semibold" style={{ color: active ? 'var(--accent)' : 'var(--text)' }}>
                {m ? m.label : f.name}
              </p>
              <p className="text-[9px] font-mono" style={{ color: 'var(--text-3)' }}>
                {f.size} bytes
              </p>
            </button>
          )
        })}
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        {meta && (
          <div className="px-4 py-2 border-b flex items-center gap-2 flex-wrap" style={{ borderColor: 'var(--border)' }}>
            <span className="text-[11px] font-bold" style={{ color: 'var(--text)' }}>{meta.label}</span>
            <span className="text-[10px]" style={{ color: 'var(--text-3)' }}>{meta.hint}</span>
            <div className="flex-1" />
            <span className="text-[10px] font-mono" style={{ color: 'var(--text-3)' }}>
              {lineCount} lines · {sel.name}
            </span>
          </div>
        )}
        <pre
          className="p-4 text-[10px] font-mono leading-relaxed overflow-auto whitespace-pre-wrap break-all"
          style={{ color: 'var(--text-2)', maxHeight: 480 }}
        >
          {loading ? 'Loading…' : (content || '(empty)')}
        </pre>
      </div>
    </div>
  )
}
