import React, { useEffect, useState, useMemo } from 'react'
import { api } from '../api.js'

const IMAGE_EXTS = new Set(['.png', '.jpg', '.jpeg', '.webp', '.gif'])

const TYPE_ORDER = [
  'report', 'nuclei', 'http', 'secrets', 'endpoints', 'url',
  'subdomain', 'port', 'dir', 'network', 'gf', 'screenshot', 'other',
]

const FILE_CATEGORIES = {
  report:    { label: 'Report & Stats',     names: ['report', 'stats'] },
  nuclei:    { label: 'Vulnerabilities',    names: ['nuclei', 'afrog', 'takeover_findings'] },
  http:      { label: 'HTTP Probe',         names: ['httpx', 'httpx_probe', 'cdncheck', 'dnsx'] },
  secrets:   { label: 'Secrets',            names: ['secretfinder', 'trufflehog', 'gitleaks', 'jsubfinder_secrets'] },
  endpoints: { label: 'Endpoints & Params', names: [
    'all_endpoints', 'linkfinder', 'jsapiscan', 'all_params', 'found_params',
    'arjun', 'x8_params', 'ffuf_params', 'param_probe', 'js_urls',
    'combined_wordlist', 'kiterunner', 'urls_with_params',
  ]},
  url:       { label: 'URLs',               names: [
    'gau', 'waybackurls', 'katana', 'hakrawler', 'urlfinder', 'waymore',
    'all_urls', 'fallparams', 'paramspider', 'paramspider_urls',
    'p_urlfinder_urls', 'p_waymore_urls', 'p_waybackurls_subs',
  ]},
  subdomain: { label: 'Subdomains',         names: [
    'p_subfinder', 'p_amass', 'p_assetfinder', 'p_findomain', 'p_chaos',
    'p_cero', 'p_gau_subs', 'p_oneforall', 'p_sublist3r', 'p_uncover',
    'p_urlfinder_subs', 'p_waymore_subs', 'p_waybackurls_subs',
    'passive_merged', 'a_puredns', 'a_shuffledns', 'a_gobuster_dns',
    'perm_alterx', 'perm_dnsgen',
    'subdomains', 'subzy', 'resolved', 'takeover', 'jsubfinder_subs', 'all_subs', 'alterx',
  ]},
  port:      { label: 'Ports',              names: ['naabu'] },
  dir:       { label: 'Directory Brute',    names: [
    'gobuster_dir', 'gobuster', 'dirsearch', 'ffuf_paths', 'feroxbuster', 'fuzzuli', 'swaggerspy',
  ]},
  network:   { label: 'ASN / Network',      names: ['asn_ipv4_cidrs', 'asn_stats', 'resolvers', 'resolvers_pure'] },
  gf:        { label: 'GF Patterns',        names: [] },
  screenshot:{ label: 'Screenshots',        names: ['gowitness'] },
}

function categorize(file) {
  if (file.path.startsWith('gf/') || file.path.startsWith('gf\\')) return 'gf'
  if (file.path.startsWith('screenshots/')) return 'screenshot'
  if (file.path.startsWith('oneforall/') || file.path.startsWith('oneforall\\')) return 'subdomain'
  const stem = file.name.replace(/\.[^.]+$/, '').toLowerCase()
  for (const [cat, def] of Object.entries(FILE_CATEGORIES)) {
    if (def.names.some(n => stem === n || stem.startsWith(n + '_') || stem.startsWith(n + '.'))) return cat
  }
  return 'other'
}

function formatBytes(n) {
  if (n === 0) return '0 B'
  if (n < 1024) return n + ' B'
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB'
  return (n / 1024 / 1024).toFixed(1) + ' MB'
}

function parseJsonFindings(content, ext) {
  const tryJsonl = src => {
    const lines = src.trim().split('\n').filter(Boolean)
    const parsed = lines.map(l => { try { return JSON.parse(l) } catch { return null } }).filter(Boolean)
    return parsed.length ? parsed : null
  }
  if (ext === '.jsonl') return tryJsonl(content) || []
  if (ext === '.json') {
    try {
      const d = JSON.parse(content)
      if (Array.isArray(d)) return d
      // arjun format: {url: {params: [...]}}
      if (d && typeof d === 'object' && !d.results && !d.findings) {
        const rows = Object.entries(d).flatMap(([url, v]) =>
          (v?.params || []).map(p => ({ _url: url, _param: p }))
        )
        if (rows.length > 0) return rows
        // empty arjun
        return []
      }
      if (d.results) return d.results
      if (d.findings) return d.findings
      return [d]
    } catch {
      return tryJsonl(content) || []
    }
  }
  return []
}

const SEV_COLOR = {
  critical: '#ff4444', high: '#f85149', medium: '#f0b429',
  low: '#3fb950', info: '#8b949e',
}

const scColor = sc =>
  sc >= 200 && sc < 300 ? '#3fb950' :
  sc >= 300 && sc < 400 ? '#d29922' :
  sc >= 400 && sc < 500 ? '#f85149' :
  sc >= 500 ? '#ff6e6e' : '#8b949e'

const ICON = { '.jsonl': '{}', '.json': '{}', '.md': '◈' }

export default function FileExplorer({ runId }) {
  const [files, setFiles] = useState([])
  const [selected, setSelected] = useState(null)
  const [content, setContent] = useState('')
  const [loadingContent, setLoadingContent] = useState(false)
  const [filter, setFilter] = useState('')
  const [showAllLines, setShowAllLines] = useState(false)

  useEffect(() => {
    api.getFiles(runId).then(data => {
      setFiles((data || []).filter(f => f.size > 0))
    }).catch(() => {})
  }, [runId])

  const open = async file => {
    if (selected?.path === file.path) return
    setSelected(file)
    setShowAllLines(false)
    if (IMAGE_EXTS.has(file.ext)) { setContent(''); return }
    setLoadingContent(true)
    try { setContent(await api.getFileContent(runId, file.path)) }
    catch { setContent('Error loading file.') }
    setLoadingContent(false)
  }

  const lc = filter.toLowerCase()
  const visible = filter ? files.filter(f => f.path.toLowerCase().includes(lc)) : files
  const groups = {}
  for (const f of visible) { const c = categorize(f); (groups[c] = groups[c] || []).push(f) }

  const ext  = selected?.ext  || ''
  const name = selected?.name || ''
  const isImage    = selected && IMAGE_EXTS.has(ext)
  const isMarkdown = ext === '.md'
  const isStats    = name === 'stats.txt' || name === 'asn_stats.txt'

  const findings = useMemo(() => {
    if (!selected || isImage || isMarkdown || isStats) return []
    if (ext !== '.json' && ext !== '.jsonl') return []
    return parseJsonFindings(content, ext)
  }, [content, selected, ext, isImage, isMarkdown, isStats])

  // JSON/JSONL table renderers
  const isNuclei     = name.startsWith('nuclei') || name.startsWith('afrog')
  const isHttpx      = name.startsWith('httpx') || name.startsWith('cdncheck') || name.startsWith('dnsx')
  const isFerox      = name.startsWith('feroxbuster')
  const isFfuf       = name.startsWith('ffuf')
  const isTrufflehog = name.startsWith('trufflehog')
  const isGitleaks   = name.startsWith('gitleaks')
  const isArjun      = name.startsWith('arjun')
  const isX8         = name.startsWith('x8')
  const isNaabu      = name.startsWith('naabu')
  const isKnownJsonType = isNuclei || isHttpx || isFerox || isFfuf || isTrufflehog || isGitleaks || isArjun || isX8 || isNaabu
  const isJsonExt = ext === '.json' || ext === '.jsonl'
  const showTable = isJsonExt && (findings.length > 0 || isKnownJsonType)

  // Special text file renderers (parsed from .txt)
  const isGobusterDns  = name === 'a_gobuster_dns.txt'
  const isGobusterDir  = name === 'gobuster_dir.txt'
  const isDirsearch    = name === 'dirsearch.txt'
  const isSpecialText  = (isGobusterDns || isGobusterDir || isDirsearch) && ext === '.txt'

  // OneForAll CSV viewer
  const isOneForAllCsv = ext === '.csv' && (
    (selected?.path || '').startsWith('oneforall') ||
    content.startsWith('id,alive,request,resolve,url,subdomain')
  )

  // Generic JSON pretty-print for unknown JSON with 0 findings
  const showJsonPretty = isJsonExt && !showTable && !!content

  const LINES_LIMIT = 500
  const lines = useMemo(() => {
    if (!content || isMarkdown || isStats || showTable || showJsonPretty || isSpecialText || isOneForAllCsv || isImage) return []
    return content.split('\n')
  }, [content, isMarkdown, isStats, showTable, showJsonPretty, isSpecialText, isOneForAllCsv, isImage])
  const displayLines = showAllLines ? lines : lines.slice(0, LINES_LIMIT)

  const recordLabel = isNaabu ? 'ports' : isFerox ? 'paths' : isFfuf ? 'results'
    : isNuclei ? 'findings' : isHttpx ? 'hosts' : isOneForAllCsv ? 'subdomains' : 'records'

  return (
    <div className="flex h-full text-xs">
      {/* ── Sidebar ── */}
      <div className="w-64 flex-shrink-0 border-r border-[#30363d] flex flex-col">
        <div className="px-3 py-2 border-b border-[#21262d]">
          <input
            className="w-full bg-[#0d1117] border border-[#30363d] rounded px-2 py-1 text-[11px] text-[#e6edf3] placeholder-[#484f58] focus:outline-none focus:border-[#388bfd]"
            placeholder="Filter files…"
            value={filter}
            onChange={e => setFilter(e.target.value)}
          />
        </div>
        <div className="flex-1 overflow-y-auto py-1">
          {files.length === 0 && <p className="px-4 text-[#484f58] text-[11px] mt-4">No output files yet.</p>}
          {TYPE_ORDER.filter(cat => groups[cat]?.length).map(cat => (
            <div key={cat}>
              <div className="px-3 pt-3 pb-1 text-[9px] font-bold uppercase tracking-widest text-[#484f58]">
                {FILE_CATEGORIES[cat]?.label || 'Other'}
                <span className="ml-1.5 text-[#30363d] font-normal">{groups[cat].length}</span>
              </div>
              {groups[cat].map(f => (
                <button
                  key={f.path}
                  onClick={() => open(f)}
                  className={`w-full text-left px-3 py-1.5 flex items-center gap-2 transition-colors
                    ${selected?.path === f.path
                      ? 'bg-[#58a6ff1a] text-[#58a6ff]'
                      : 'text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#161b22]'}`}
                >
                  <span className="text-[10px] w-4 shrink-0 text-center opacity-50">{ICON[f.ext] || '≡'}</span>
                  <span className="truncate flex-1 font-mono text-[11px]">{f.path.includes('/') ? f.path : f.name}</span>
                  <span className="text-[10px] shrink-0 tabular-nums text-[#484f58]">{formatBytes(f.size)}</span>
                </button>
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* ── Content pane ── */}
      <div className="flex-1 overflow-hidden flex flex-col min-w-0">
        {!selected ? (
          <div className="flex-1 flex items-center justify-center text-[#484f58] text-[11px]">Select a file to preview</div>
        ) : (
          <>
            <div className="px-4 py-2.5 border-b border-[#30363d] flex items-center gap-3 flex-shrink-0 bg-[#161b22]">
              <span className="font-mono text-[#e6edf3] text-[11px]">{selected.name}</span>
              <span className="text-[#30363d]">·</span>
              <span className="text-[#8b949e] text-[10px] tabular-nums">{formatBytes(selected.size)}</span>
              {showTable && findings.length > 0 && (
                <span className="text-[10px] text-[#58a6ff]">· {findings.length} {recordLabel}</span>
              )}
              {showTable && findings.length === 0 && (
                <span className="text-[10px] text-[#484f58]">· 0 {recordLabel}</span>
              )}
              {isOneForAllCsv && content && (
                <span className="text-[10px] text-[#58a6ff]">
                  · {Math.max(0, content.trim().split('\n').length - 1)} subdomains
                </span>
              )}
              {!showTable && !showJsonPretty && !isSpecialText && lines.length > 0 && (
                <span className="text-[10px] text-[#8b949e]">· {lines.length} lines</span>
              )}
              <a href={`/api/v1/runs/${runId}/files/${selected.path}`} target="_blank" rel="noreferrer"
                className="ml-auto text-[10px] text-[#484f58] hover:text-[#8b949e] transition-colors">↗ raw</a>
            </div>

            {loadingContent ? (
              <div className="flex-1 flex items-center justify-center text-[#484f58]">Loading…</div>
            ) : isImage ? (
              <div className="flex-1 overflow-auto flex items-center justify-center p-6 bg-[#0d1117]">
                <img src={`/api/v1/runs/${runId}/files/${selected.path}`} alt={selected.name} className="max-w-full max-h-full object-contain rounded" />
              </div>
            ) : isMarkdown ? (
              <div className="flex-1 overflow-auto px-6 py-5 bg-[#0d1117]"><MarkdownView content={content} /></div>
            ) : isStats ? (
              <div className="flex-1 overflow-auto p-4 bg-[#0d1117]"><StatsView content={content} /></div>
            ) : showTable ? (
              <div className="flex-1 overflow-auto">
                {isNuclei     ? <NucleiTable findings={findings} />
                  : isHttpx   ? <HttpxTable findings={findings} />
                  : isFerox   ? <FeroxbusterTable findings={findings} />
                  : isFfuf    ? <FfufTable findings={findings} />
                  : isTrufflehog ? <TrufflehogTable findings={findings} />
                  : isGitleaks   ? <GitleaksTable findings={findings} />
                  : isArjun      ? <ArjunTable findings={findings} />
                  : isX8         ? <X8Table findings={findings} />
                  : isNaabu      ? <NaabuTable findings={findings} />
                  : <GenericJsonTable findings={findings} />
                }
              </div>
            ) : isOneForAllCsv ? (
              <div className="flex-1 overflow-auto">
                <OneForAllCsvView content={content} />
              </div>
            ) : isSpecialText ? (
              <div className="flex-1 overflow-auto">
                {isGobusterDns ? <GobusterDnsView content={content} />
                  : isGobusterDir ? <GobusterDirView content={content} />
                  : isDirsearch   ? <DirsearchView content={content} />
                  : null
                }
              </div>
            ) : showJsonPretty ? (
              <div className="flex-1 overflow-auto bg-[#0d1117]"><JsonPrettyView content={content} ext={ext} /></div>
            ) : (
              <div className="flex-1 overflow-auto bg-[#0d1117]">
                <TextFileView lines={displayLines} total={lines.length} limit={LINES_LIMIT} onShowAll={() => setShowAllLines(true)} />
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

/* ─── JsonPrettyView ───────────────────────────────────────── */
function JsonPrettyView({ content, ext }) {
  const pretty = useMemo(() => {
    if (ext === '.json') {
      try { return JSON.stringify(JSON.parse(content), null, 2) } catch {}
    }
    const lines = content.trim().split('\n').filter(Boolean).slice(0, 50)
    return lines.map(l => { try { return JSON.stringify(JSON.parse(l), null, 2) } catch { return l } })
      .join('\n\n─────────────────────\n\n')
  }, [content, ext])
  return (
    <pre className="px-4 py-3 font-mono text-[11px] leading-[1.8] text-[#8b949e] whitespace-pre overflow-auto h-full">{pretty}</pre>
  )
}

/* ─── MarkdownView ─────────────────────────────────────────── */
function renderInline(text) {
  return text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((seg, i) => {
    if (seg.startsWith('**') && seg.endsWith('**'))
      return <strong key={i} className="text-[#e6edf3] font-semibold">{seg.slice(2, -2)}</strong>
    if (seg.startsWith('`') && seg.endsWith('`'))
      return <code key={i} className="bg-[#161b22] border border-[#30363d] rounded px-1 py-0.5 font-mono text-[10px] text-[#79c0ff]">{seg.slice(1, -1)}</code>
    return seg
  })
}

function MarkdownView({ content }) {
  const els = []
  let i = 0
  const lines = content.split('\n')
  while (i < lines.length) {
    const line = lines[i]
    if (line.startsWith('# '))
      els.push(<h1 key={i} className="text-[#e6edf3] text-xl font-bold mt-1 mb-3">{renderInline(line.slice(2))}</h1>)
    else if (line.startsWith('## '))
      els.push(<h2 key={i} className="text-[#58a6ff] text-sm font-semibold mt-6 mb-2 pb-1 border-b border-[#21262d]">{renderInline(line.slice(3))}</h2>)
    else if (line.startsWith('### '))
      els.push(<h3 key={i} className="text-[#8b949e] text-[12px] font-semibold mt-4 mb-1">{renderInline(line.slice(4))}</h3>)
    else if (/^[-*] /.test(line)) {
      const items = []
      while (i < lines.length && /^[-*] /.test(lines[i])) {
        items.push(<li key={i} className="text-[#8b949e] text-[12px] leading-relaxed">{renderInline(lines[i].slice(2))}</li>)
        i++
      }
      els.push(<ul key={`ul${i}`} className="list-disc list-inside space-y-0.5 my-2 pl-1">{items}</ul>)
      continue
    } else if (line.trim() === '')
      els.push(<div key={i} className="h-2" />)
    else
      els.push(<p key={i} className="text-[#8b949e] text-[12px] leading-relaxed">{renderInline(line)}</p>)
    i++
  }
  return <div className="max-w-2xl space-y-0.5">{els}</div>
}

/* ─── StatsView ────────────────────────────────────────────── */
function StatsView({ content }) {
  const pairs = content.trim().split('\n').filter(Boolean).map(line => {
    const idx = line.indexOf(':')
    return idx === -1 ? { key: line, value: '' } : { key: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() }
  })
  return (
    <div className="max-w-lg">
      <table className="w-full text-[11px] border border-[#21262d] rounded overflow-hidden">
        <tbody>
          {pairs.map((p, i) => (
            <tr key={i} className={`${i % 2 === 0 ? 'bg-[#161b22]' : 'bg-[#0d1117]'} border-b border-[#21262d] last:border-0`}>
              <td className="px-4 py-2 text-[#484f58] font-mono w-52 whitespace-nowrap">{p.key}</td>
              <td className="px-4 py-2 text-[#e6edf3] font-mono font-medium">{p.value || <span className="text-[#30363d]">—</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/* ─── TextFileView ─────────────────────────────────────────── */
const URL_RE = /https?:\/\/[^\s]+/g
function highlightLine(line) {
  const parts = []
  let last = 0; let m
  URL_RE.lastIndex = 0
  while ((m = URL_RE.exec(line)) !== null) {
    if (m.index > last) parts.push(line.slice(last, m.index))
    parts.push(<a key={m.index} href={m[0]} target="_blank" rel="noreferrer" className="text-[#58a6ff] hover:underline">{m[0]}</a>)
    last = m.index + m[0].length
  }
  if (last < line.length) parts.push(line.slice(last))
  return parts.length > 1 ? parts : line
}

function TextFileView({ lines, total, limit, onShowAll }) {
  if (!lines.length) return <div className="px-4 py-3 text-[#484f58] text-[11px]">(empty)</div>
  return (
    <div>
      <table className="w-full font-mono text-[11px] border-collapse">
        <tbody>
          {lines.map((line, i) => (
            <tr key={i} className="hover:bg-[#161b22]">
              <td className="select-none text-right pr-3 pl-3 py-[2px] text-[#484f58] text-[10px] tabular-nums w-10 border-r border-[#21262d] shrink-0">{i + 1}</td>
              <td className="pl-4 pr-3 py-[2px] text-[#8b949e] break-all leading-relaxed">{highlightLine(line)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {total > limit && lines.length < total && (
        <div className="px-4 py-4 text-center border-t border-[#21262d]">
          <button onClick={onShowAll} className="text-[11px] text-[#484f58] hover:text-[#8b949e] transition-colors">
            Show remaining {total - limit} lines ↓
          </button>
        </div>
      )}
    </div>
  )
}

/* ─── GobusterDnsView ──────────────────────────────────────── */
// Format: `subdomain.example.com  172.x.x.x,172.x.x.x,...`
function GobusterDnsView({ content }) {
  const rows = content.trim().split('\n').filter(Boolean).map(line => {
    const parts = line.trim().split(/\s+/)
    return { host: parts[0] || '', ips: parts.slice(1).join(' ') }
  })
  if (!rows.length) return <Empty>No resolved hosts.</Empty>
  return (
    <table className="w-full text-[11px]">
      <THead cols={['Host', 'IP(s)']} />
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="border-b border-[#21262d] hover:bg-[#161b22]">
            <td className="px-4 py-1.5 font-mono text-[10px] text-[#e6edf3]">{r.host}</td>
            <td className="px-4 py-1.5 font-mono text-[10px] text-[#8b949e]">{r.ips || <span className="text-[#484f58]">—</span>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/* ─── GobusterDirView ──────────────────────────────────────── */
// Format: `/path (Status: 200) [Size: 1234]`
function GobusterDirView({ content }) {
  const rows = content.trim().split('\n').filter(Boolean).map(line => {
    const statusM = line.match(/\(Status:\s*(\d+)\)/)
    const sizeM   = line.match(/\[Size:\s*(\d+)\]/)
    const path    = line.split('(')[0].trim()
    return { path, status: statusM ? +statusM[1] : null, size: sizeM ? +sizeM[1] : null }
  }).filter(r => r.path)
  if (!rows.length) return <Empty>No paths found.</Empty>
  return (
    <table className="w-full text-[11px]">
      <THead cols={['Status', 'Path', 'Size']} />
      <tbody>
        {rows.map((r, i) => {
          const color = r.status ? scColor(r.status) : '#8b949e'
          return (
            <tr key={i} className="border-b border-[#21262d] hover:bg-[#161b22]">
              <td className="px-4 py-1.5 whitespace-nowrap w-20">
                {r.status && <StatusBadge code={r.status} color={color} />}
              </td>
              <td className="px-4 py-1.5 font-mono text-[10px] text-[#58a6ff]">{r.path}</td>
              <td className="px-4 py-1.5 text-[#484f58] text-[10px] tabular-nums">{r.size != null ? formatBytes(r.size) : '—'}</td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

/* ─── DirsearchView ────────────────────────────────────────── */
// Format: `200   1.2KB   /path` (dirsearch --format=plain)
function DirsearchView({ content }) {
  const rows = content.trim().split('\n').filter(l => !l.startsWith('#') && l.trim()).map(line => {
    const parts = line.trim().split(/\s+/)
    if (parts.length < 2) return null
    const status = +parts[0]
    const path   = parts[parts.length - 1]
    const size   = parts.length >= 3 ? parts[1] : ''
    return isNaN(status) ? null : { status, size, path }
  }).filter(Boolean)
  if (!rows.length) return <Empty>No paths found.</Empty>
  return (
    <table className="w-full text-[11px]">
      <THead cols={['Status', 'Size', 'Path']} />
      <tbody>
        {rows.map((r, i) => {
          const color = scColor(r.status)
          return (
            <tr key={i} className="border-b border-[#21262d] hover:bg-[#161b22]">
              <td className="px-4 py-1.5 whitespace-nowrap w-20"><StatusBadge code={r.status} color={color} /></td>
              <td className="px-4 py-1.5 text-[#484f58] text-[10px] tabular-nums whitespace-nowrap">{r.size}</td>
              <td className="px-4 py-1.5 font-mono text-[10px] text-[#58a6ff]">{r.path}</td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

/* ─── NucleiTable ──────────────────────────────────────────── */
function NucleiTable({ findings }) {
  const [expanded, setExpanded] = React.useState(null)
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  findings.forEach(f => { const s = f.info?.severity || 'info'; sev[s] = (sev[s] || 0) + 1 })
  if (!findings.length) return <Empty>No findings.</Empty>
  return (
    <div>
      <div className="flex gap-5 px-4 py-2.5 border-b border-[#30363d] text-[11px]">
        {Object.entries(sev).filter(([, v]) => v > 0).map(([k, v]) => (
          <span key={k} style={{ color: SEV_COLOR[k] }}><span className="font-bold">{v}</span> {k}</span>
        ))}
      </div>
      <table className="w-full text-[11px]">
        <THead cols={['Severity', 'Template', 'Matched At', 'Extracted']} />
        <tbody>
          {findings.map((f, i) => {
            const sev = f.info?.severity || 'info'
            const tid = f['template-id']
            const tname = f.info?.name
            const matched = f['matched-at'] || f.host || ''
            const extracted = (f['extracted-results'] || []).join(', ')
            const isOpen = expanded === i
            return (
              <React.Fragment key={i}>
                <tr className="border-b border-[#21262d] hover:bg-[#161b22] cursor-pointer" onClick={() => setExpanded(isOpen ? null : i)}>
                  <td className="px-4 py-2 whitespace-nowrap w-24">
                    <span className="text-[9px] font-bold px-1.5 py-0.5 rounded"
                      style={{ color: SEV_COLOR[sev], background: `${SEV_COLOR[sev]}22`, border: `1px solid ${SEV_COLOR[sev]}44` }}>
                      {sev.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-2 font-mono text-[10px] text-[#e6edf3] max-w-[180px] truncate">{tid || tname || '—'}</td>
                  <td className="px-4 py-2 font-mono text-[10px] text-[#58a6ff] max-w-xs truncate">{matched}</td>
                  <td className="px-4 py-2 font-mono text-[10px] text-[#3fb950] max-w-xs truncate">{extracted}</td>
                </tr>
                {isOpen && (
                  <tr className="border-b border-[#30363d] bg-[#0d1117]">
                    <td colSpan={4} className="px-6 py-3 text-[11px] space-y-1.5">
                      {tid && <Row k="template-id" v={tid} mono />}
                      {tname && <Row k="name" v={tname} />}
                      {matched && <Row k="matched-at" v={<a href={matched} target="_blank" rel="noreferrer" className="text-[#58a6ff] hover:underline break-all">{matched}</a>} />}
                      {f.ip && <Row k="ip" v={f.ip} mono />}
                      {f.info?.description && <Row k="description" v={f.info.description} />}
                      {extracted && <Row k="extracted" v={<span className="text-[#3fb950]">{extracted}</span>} />}
                      {f['curl-command'] && (
                        <pre className="text-[10px] bg-[#161b22] border border-[#30363d] rounded p-2 overflow-x-auto whitespace-pre-wrap break-all text-[#8b949e] mt-1">{f['curl-command']}</pre>
                      )}
                    </td>
                  </tr>
                )}
              </React.Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

/* ─── HttpxTable ───────────────────────────────────────────── */
function HttpxTable({ findings }) {
  const [expanded, setExpanded] = React.useState(null)
  if (!findings.length) return <Empty>No hosts.</Empty>
  return (
    <table className="w-full text-[11px]">
      <THead cols={['Status', 'URL', 'Title', 'Tech / CDN', 'Size']} />
      <tbody>
        {findings.map((f, i) => {
          const color = scColor(f.status_code)
          const isOpen = expanded === i
          const tech = f.tech || []
          const cdn  = f.cdn_name || (f.cdn ? 'CDN' : '')
          return (
            <React.Fragment key={i}>
              <tr className="border-b border-[#21262d] hover:bg-[#161b22] cursor-pointer" onClick={() => setExpanded(isOpen ? null : i)}>
                <td className="px-4 py-2 whitespace-nowrap w-16"><StatusBadge code={f.status_code} color={color} /></td>
                <td className="px-4 py-2 font-mono text-[10px] text-[#58a6ff] max-w-xs">
                  <a href={f.url} target="_blank" rel="noreferrer" className="hover:underline block truncate" onClick={e => e.stopPropagation()}>{f.url}</a>
                </td>
                <td className="px-4 py-2 text-[#e6edf3] text-[10px] max-w-[180px] truncate">{f.title || <span className="text-[#484f58]">—</span>}</td>
                <td className="px-4 py-2 text-[#8b949e] text-[10px] max-w-[160px] truncate">
                  {[...tech.slice(0, 2), cdn].filter(Boolean).join(', ')}
                  {tech.length > 2 && <span className="text-[#484f58]"> +{tech.length - 2}</span>}
                </td>
                <td className="px-4 py-2 text-[#484f58] text-[10px] tabular-nums whitespace-nowrap">{formatBytes(f.content_length || 0)}</td>
              </tr>
              {isOpen && (
                <tr className="border-b border-[#30363d] bg-[#0d1117]">
                  <td colSpan={5} className="px-6 py-3 text-[11px] space-y-1.5">
                    {f.url && <Row k="url" v={<a href={f.url} target="_blank" rel="noreferrer" className="text-[#58a6ff] hover:underline break-all">{f.url}</a>} />}
                    {f.final_url && f.final_url !== f.url && <Row k="redirect" v={f.final_url} mono />}
                    {f.ip && <Row k="ip" v={f.ip} mono />}
                    {cdn && <Row k="cdn" v={cdn} mono />}
                    {f.webserver && <Row k="server" v={f.webserver} mono />}
                    {tech.length > 0 && <Row k="tech" v={tech.join(', ')} />}
                    {f.words != null && <Row k="words / lines" v={`${f.words} / ${f.lines}`} mono />}
                  </td>
                </tr>
              )}
            </React.Fragment>
          )
        })}
      </tbody>
    </table>
  )
}

/* ─── FeroxbusterTable ─────────────────────────────────────── */
function FeroxbusterTable({ findings }) {
  const rows = findings.filter(f => f.type === 'response' && f.status !== 404 && f.url)
    .sort((a, b) => a.status - b.status)
  if (!rows.length) return <Empty>No responses (all 404 or no data).</Empty>
  return (
    <table className="w-full text-[11px]">
      <THead sticky cols={['Status', 'Method', 'URL', 'Size', 'Words', 'Lines']} />
      <tbody>
        {rows.map((f, i) => {
          const color = scColor(f.status)
          return (
            <tr key={i} className="border-b border-[#21262d] hover:bg-[#161b22]">
              <td className="px-4 py-1.5 whitespace-nowrap w-20"><StatusBadge code={f.status} color={color} /></td>
              <td className="px-4 py-1.5 text-[#484f58] text-[10px] w-14">{f.method || 'GET'}</td>
              <td className="px-4 py-1.5 font-mono text-[10px] text-[#58a6ff] max-w-md">
                <a href={f.url} target="_blank" rel="noreferrer" className="hover:underline block truncate">{f.url}</a>
              </td>
              <td className="px-4 py-1.5 text-[#484f58] text-[10px] tabular-nums whitespace-nowrap">{formatBytes(f.content_length || f.size || 0)}</td>
              <td className="px-4 py-1.5 text-[#484f58] text-[10px] tabular-nums">{f.word_count ?? '—'}</td>
              <td className="px-4 py-1.5 text-[#484f58] text-[10px] tabular-nums">{f.line_count ?? '—'}</td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

/* ─── FfufTable ────────────────────────────────────────────── */
function FfufTable({ findings }) {
  if (!findings.length) return <Empty>No results.</Empty>
  return (
    <table className="w-full text-[11px]">
      <THead sticky cols={['Status', 'URL / FUZZ value', 'Length', 'Words', 'Lines']} />
      <tbody>
        {findings.map((f, i) => {
          const color = scColor(f.status)
          const url   = f.url || f.input?.FUZZ || ''
          return (
            <tr key={i} className="border-b border-[#21262d] hover:bg-[#161b22]">
              <td className="px-4 py-1.5 w-20"><StatusBadge code={f.status} color={color} /></td>
              <td className="px-4 py-1.5 font-mono text-[10px] text-[#58a6ff] max-w-md">
                {url ? <a href={url.startsWith('http') ? url : undefined} target="_blank" rel="noreferrer" className="hover:underline block truncate">{url}</a>
                     : <span className="text-[#484f58]">—</span>}
              </td>
              <td className="px-4 py-1.5 text-[#484f58] text-[10px] tabular-nums">{f.length ?? '—'}</td>
              <td className="px-4 py-1.5 text-[#484f58] text-[10px] tabular-nums">{f.words ?? '—'}</td>
              <td className="px-4 py-1.5 text-[#484f58] text-[10px] tabular-nums">{f.lines ?? '—'}</td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

/* ─── NaabuTable ───────────────────────────────────────────── */
function NaabuTable({ findings }) {
  if (!findings.length) return <Empty>No open ports found.</Empty>
  const byHost = {}
  findings.forEach(f => {
    const h = f.host || f.ip || ''
    ;(byHost[h] = byHost[h] || []).push(f.port)
  })
  return (
    <table className="w-full text-[11px]">
      <THead cols={['Host / IP', 'Open Ports', 'Protocol']} />
      <tbody>
        {Object.entries(byHost).map(([host, ports], i) => (
          <tr key={i} className="border-b border-[#21262d] hover:bg-[#161b22]">
            <td className="px-4 py-2 font-mono text-[10px] text-[#e6edf3]">{host}</td>
            <td className="px-4 py-2 font-mono text-[10px] text-[#58a6ff]">
              {ports.sort((a, b) => a - b).map((p, j) => (
                <span key={j} className="inline-block mr-1.5 px-1 py-0.5 bg-[#58a6ff22] border border-[#58a6ff44] rounded text-[9px]">{p}</span>
              ))}
            </td>
            <td className="px-4 py-2 text-[#484f58] text-[10px]">{findings.find(f => (f.host || f.ip) === host)?.protocol || 'tcp'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/* ─── TrufflehogTable ──────────────────────────────────────── */
function TrufflehogTable({ findings }) {
  const [expanded, setExpanded] = React.useState(null)
  if (!findings.length) return <Empty>No secrets found.</Empty>
  return (
    <table className="w-full text-[11px]">
      <THead cols={['Verified', 'Detector', 'File']} />
      <tbody>
        {findings.map((f, i) => {
          const verified = f.Verified || f.verified
          const isOpen   = expanded === i
          return (
            <React.Fragment key={i}>
              <tr className="border-b border-[#21262d] hover:bg-[#161b22] cursor-pointer" onClick={() => setExpanded(isOpen ? null : i)}>
                <td className="px-4 py-2 w-24">
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${verified ? 'text-[#f85149] bg-[#f8514922]' : 'text-[#8b949e] bg-[#8b949e22]'}`}>
                    {verified ? 'VERIFIED' : 'unverified'}
                  </span>
                </td>
                <td className="px-4 py-2 font-mono text-[10px] text-[#e6edf3]">{f.DetectorName || f.detector_name || '—'}</td>
                <td className="px-4 py-2 font-mono text-[10px] text-[#8b949e] max-w-xs truncate">{f.SourceMetadata?.Data?.Filesystem?.file || '—'}</td>
              </tr>
              {isOpen && (
                <tr className="border-b border-[#30363d] bg-[#0d1117]">
                  <td colSpan={3} className="px-6 py-3">
                    <pre className="text-[10px] bg-[#161b22] border border-[#30363d] rounded p-2 overflow-x-auto whitespace-pre-wrap break-all text-[#8b949e]">{JSON.stringify(f, null, 2)}</pre>
                  </td>
                </tr>
              )}
            </React.Fragment>
          )
        })}
      </tbody>
    </table>
  )
}

/* ─── GitleaksTable ────────────────────────────────────────── */
function GitleaksTable({ findings }) {
  const [expanded, setExpanded] = React.useState(null)
  if (!findings.length) return <Empty>No secrets found.</Empty>
  return (
    <table className="w-full text-[11px]">
      <THead cols={['Rule', 'File : Line', 'Secret']} />
      <tbody>
        {findings.map((f, i) => {
          const secret = f.Secret || f.secret || ''
          const isOpen = expanded === i
          return (
            <React.Fragment key={i}>
              <tr className="border-b border-[#21262d] hover:bg-[#161b22] cursor-pointer" onClick={() => setExpanded(isOpen ? null : i)}>
                <td className="px-4 py-2 font-mono text-[10px] text-[#e6edf3]">{f.RuleID || f.ruleId || '—'}</td>
                <td className="px-4 py-2 font-mono text-[10px] text-[#8b949e]">{f.File || f.file || '—'}{f.StartLine ? `:${f.StartLine}` : ''}</td>
                <td className="px-4 py-2 font-mono text-[10px] text-[#f0b429] max-w-xs truncate">{secret.slice(0, 48)}{secret.length > 48 ? '…' : ''}</td>
              </tr>
              {isOpen && (
                <tr className="border-b border-[#30363d] bg-[#0d1117]">
                  <td colSpan={3} className="px-6 py-3 text-[11px] space-y-1.5">
                    {f.Description && <Row k="description" v={f.Description} />}
                    {secret && <Row k="secret" v={<span className="text-[#f0b429] break-all">{secret}</span>} />}
                    {f.Match && <Row k="match" v={f.Match} mono />}
                  </td>
                </tr>
              )}
            </React.Fragment>
          )
        })}
      </tbody>
    </table>
  )
}

/* ─── ArjunTable ───────────────────────────────────────────── */
// Handles both:
//   array of {_url, _param} (already flattened by parseJsonFindings)
//   array of {params: [], url: ...}
function ArjunTable({ findings }) {
  const rows = useMemo(() => {
    if (!findings.length) return []
    if ('_param' in findings[0]) return findings.map(f => ({ url: f._url, param: f._param }))
    return findings.flatMap(f => (f.params || []).map(p => ({ url: f.url || f.endpoint || '', param: p })))
  }, [findings])
  if (!rows.length) return <Empty>No parameters found.</Empty>
  return (
    <table className="w-full text-[11px]">
      <THead cols={['Parameter', 'Endpoint']} />
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="border-b border-[#21262d] hover:bg-[#161b22]">
            <td className="px-4 py-1.5 font-mono text-[10px] text-[#3fb950] w-48">{r.param}</td>
            <td className="px-4 py-1.5 font-mono text-[10px] text-[#8b949e] truncate max-w-md">{r.url || '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/* ─── X8Table ──────────────────────────────────────────────── */
function X8Table({ findings }) {
  if (!findings.length) return <Empty>No parameters found.</Empty>
  return (
    <table className="w-full text-[11px]">
      <THead cols={['Parameter', 'Method', 'Endpoint']} />
      <tbody>
        {findings.map((f, i) => (
          <tr key={i} className="border-b border-[#21262d] hover:bg-[#161b22]">
            <td className="px-4 py-1.5 font-mono text-[10px] text-[#3fb950] w-48">{f.name || f.param || '—'}</td>
            <td className="px-4 py-1.5 text-[10px] text-[#484f58] w-16">{f.method || 'GET'}</td>
            <td className="px-4 py-1.5 font-mono text-[10px] text-[#8b949e] truncate max-w-md">{f.url || '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/* ─── GenericJsonTable ─────────────────────────────────────── */
function GenericJsonTable({ findings }) {
  const [expanded, setExpanded] = React.useState(null)
  if (!findings.length) return <Empty>No data.</Empty>
  const keys = Object.keys(findings[0]).filter(k => !k.startsWith('_')).slice(0, 5)
  return (
    <table className="w-full text-[11px]">
      <THead cols={keys} />
      <tbody>
        {findings.map((f, i) => {
          const isOpen = expanded === i
          return (
            <React.Fragment key={i}>
              <tr className="border-b border-[#21262d] hover:bg-[#161b22] cursor-pointer" onClick={() => setExpanded(isOpen ? null : i)}>
                {keys.map(k => (
                  <td key={k} className="px-4 py-2 font-mono text-[10px] text-[#8b949e] max-w-xs truncate">
                    {typeof f[k] === 'object' ? JSON.stringify(f[k]) : String(f[k] ?? '')}
                  </td>
                ))}
              </tr>
              {isOpen && (
                <tr className="border-b border-[#30363d] bg-[#0d1117]">
                  <td colSpan={keys.length} className="px-6 py-3">
                    <pre className="text-[10px] bg-[#161b22] border border-[#30363d] rounded p-2 overflow-x-auto whitespace-pre-wrap break-all text-[#8b949e]">{JSON.stringify(f, null, 2)}</pre>
                  </td>
                </tr>
              )}
            </React.Fragment>
          )
        })}
      </tbody>
    </table>
  )
}

/* ─── Shared UI helpers ────────────────────────────────────── */
function THead({ cols, sticky }) {
  return (
    <thead className={sticky ? 'sticky top-0 z-10 bg-[#0d1117]' : ''}>
      <tr className="border-b border-[#30363d]">
        {cols.map(h => (
          <th key={h} className="px-4 py-2 text-left text-[9px] font-bold uppercase tracking-widest text-[#484f58]">{h}</th>
        ))}
      </tr>
    </thead>
  )
}

function StatusBadge({ code, color }) {
  return (
    <span className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded"
      style={{ color, background: `${color}22`, border: `1px solid ${color}44` }}>
      {code}
    </span>
  )
}

function Row({ k, v, mono }) {
  return (
    <div>
      <span className="text-[#484f58]">{k}: </span>
      <span className={mono ? 'font-mono text-[#8b949e]' : 'text-[#8b949e]'}>{v}</span>
    </div>
  )
}

function Empty({ children }) {
  return <div className="px-6 py-8 text-[#484f58] text-[11px] text-center">{children}</div>
}

/* ─── OneForAllCsvView ─────────────────────────────────────── */
// Renders the OneForAll result CSV: id,alive,request,resolve,url,subdomain,level,
//   cname,ip,public,cdn,port,status,reason,title,banner,cidr,asn,org,addr,isp,source
function parseOneForAllCsv(content) {
  const rawLines = content.trim().split('\n').filter(Boolean)
  if (rawLines.length < 2) return { headers: [], rows: [] }
  const headers = rawLines[0].split(',')
  const rows = rawLines.slice(1).map(line => {
    // CSV has quoted fields that may contain commas — do a simple state-machine parse
    const fields = []
    let cur = '', inQ = false
    for (let i = 0; i < line.length; i++) {
      const c = line[i]
      if (c === "'" && !inQ) { inQ = true; continue }
      if (c === "'" && inQ)  { inQ = false; continue }
      if (c === ',' && !inQ) { fields.push(cur); cur = ''; continue }
      cur += c
    }
    fields.push(cur)
    const obj = {}
    headers.forEach((h, i) => { obj[h.trim()] = (fields[i] || '').trim() })
    return obj
  })
  return { headers, rows }
}

function OneForAllCsvView({ content }) {
  const { rows } = parseOneForAllCsv(content)
  const [filter, setFilter] = React.useState('')
  const [aliveOnly, setAliveOnly] = React.useState(false)

  const filtered = rows.filter(r => {
    if (aliveOnly && r.alive !== '1') return false
    if (!filter) return true
    const q = filter.toLowerCase()
    return (r.subdomain || '').toLowerCase().includes(q) ||
           (r.ip || '').includes(q) ||
           (r.title || '').toLowerCase().includes(q) ||
           (r.source || '').toLowerCase().includes(q)
  })

  if (!rows.length) return <Empty>No OneForAll results.</Empty>

  return (
    <div className="flex flex-col h-full">
      {/* toolbar */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-[#21262d] bg-[#161b22] flex-shrink-0">
        <input
          className="bg-[#0d1117] border border-[#30363d] rounded px-2 py-1 text-[11px] text-[#e6edf3] placeholder-[#484f58] focus:outline-none focus:border-[#388bfd] w-56"
          placeholder="Filter subdomain / IP / title…"
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />
        <label className="flex items-center gap-1.5 text-[11px] text-[#8b949e] cursor-pointer select-none">
          <input type="checkbox" checked={aliveOnly} onChange={e => setAliveOnly(e.target.checked)}
            className="accent-[#58a6ff]" />
          Alive only
        </label>
        <span className="ml-auto text-[10px] text-[#484f58] tabular-nums">
          {filtered.length} / {rows.length} subdomains
        </span>
      </div>
      {/* table */}
      <div className="flex-1 overflow-auto bg-[#0d1117]">
        <table className="w-full text-[11px] border-collapse min-w-[900px]">
          <thead className="sticky top-0 z-10 bg-[#161b22]">
            <tr className="border-b border-[#30363d]">
              {['Subdomain','IP','Port','Status','CDN','Title','Source'].map(h => (
                <th key={h} className="px-3 py-2 text-left text-[9px] font-bold uppercase tracking-widest text-[#484f58] whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((r, i) => {
              const alive = r.alive === '1'
              const cdn   = r.cdn   === '1'
              const sc    = parseInt(r.status) || 0
              const color = sc >= 200 && sc < 300 ? '#3fb950'
                          : sc >= 300 && sc < 400 ? '#d29922'
                          : sc >= 400 && sc < 500 ? '#f85149'
                          : sc >= 500 ? '#ff6e6e' : '#484f58'
              return (
                <tr key={i} className="border-b border-[#21262d] hover:bg-[#161b22]">
                  {/* Subdomain */}
                  <td className="px-3 py-1.5 font-mono text-[10px]">
                    <span style={{ color: alive ? '#e6edf3' : '#484f58' }}>{r.subdomain || '—'}</span>
                    {!alive && <span className="ml-1.5 text-[9px] text-[#484f58]">(dead)</span>}
                  </td>
                  {/* IP */}
                  <td className="px-3 py-1.5 font-mono text-[10px] text-[#8b949e] whitespace-nowrap">{r.ip || '—'}</td>
                  {/* Port */}
                  <td className="px-3 py-1.5 text-[10px] text-[#8b949e] tabular-nums">{r.port || '—'}</td>
                  {/* Status */}
                  <td className="px-3 py-1.5">
                    {sc ? (
                      <StatusBadge code={sc} color={color} />
                    ) : <span className="text-[#484f58] text-[10px]">—</span>}
                  </td>
                  {/* CDN */}
                  <td className="px-3 py-1.5 text-[10px]">
                    {cdn
                      ? <span className="text-[#d29922] bg-[#d2992222] border border-[#d2992244] rounded px-1.5 py-0.5 font-mono text-[9px]">CDN</span>
                      : <span className="text-[#484f58]">—</span>}
                  </td>
                  {/* Title */}
                  <td className="px-3 py-1.5 text-[10px] text-[#8b949e] max-w-[260px] truncate" title={r.title}>{r.title || '—'}</td>
                  {/* Source */}
                  <td className="px-3 py-1.5 text-[10px] text-[#484f58]">{r.source || '—'}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {!filtered.length && (
          <div className="px-6 py-8 text-[#484f58] text-[11px] text-center">No matching subdomains.</div>
        )}
      </div>
    </div>
  )
}
