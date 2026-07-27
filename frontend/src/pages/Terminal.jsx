import React, { useEffect, useRef, useState, useCallback } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebglAddon } from '@xterm/addon-webgl'
import { Unicode11Addon } from '@xterm/addon-unicode11'
import { WebLinksAddon } from '@xterm/addon-web-links'
import { SerializeAddon } from '@xterm/addon-serialize'
import '@xterm/xterm/css/xterm.css'

// ── Module-level session store — survives React unmount/remount ───────────────
const _session = {
  id:       null,   // reused on remount to reconnect same PTY
  snapshot: '',     // serialized screen content restored on remount
}

function getOrCreateSessionId() {
  if (!_session.id)
    _session.id = Math.random().toString(36).slice(2, 10) + Date.now().toString(36)
  return _session.id
}

function termWsUrl(sessionId) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${location.host}/ws/terminal/${sessionId}`
}

const STATUS_COLOR = {
  connecting:   'bg-yellow-400 animate-pulse',
  connected:    'bg-[#3fb950]',
  disconnected: 'bg-[#8b949e]',
  error:        'bg-[#ff7b72]',
}

export default function TerminalPage() {
  const containerRef  = useRef(null)
  const termRef       = useRef(null)
  const fitRef        = useRef(null)
  const wsRef         = useRef(null)
  const roRef         = useRef(null)
  const serializeRef  = useRef(null)
  const [status, setStatus] = useState('disconnected')

  const connect = useCallback((sid, resume) => {
    wsRef.current?.close()
    termRef.current?.dispose()
    roRef.current?.disconnect()
    setStatus('connecting')

    const term = new Terminal({
      theme: {
        background:          '#0d1117',
        foreground:          '#e6edf3',
        cursor:              '#58a6ff',
        cursorAccent:        '#0d1117',
        selectionBackground: '#264f7844',
        black:   '#21262d',  brightBlack:   '#6e7681',
        red:     '#ff7b72',  brightRed:     '#ffa198',
        green:   '#3fb950',  brightGreen:   '#56d364',
        yellow:  '#d29922',  brightYellow:  '#e3b341',
        blue:    '#58a6ff',  brightBlue:    '#79c0ff',
        magenta: '#bc8cff',  brightMagenta: '#d2a8ff',
        cyan:    '#39c5cf',  brightCyan:    '#56d4dd',
        white:   '#b1bac4',  brightWhite:   '#f0f6fc',
      },
      fontFamily: '"Cascadia Code", "Fira Code", "JetBrains Mono", "Consolas", monospace',
      fontSize: 14,
      lineHeight: 1.45,
      cursorBlink: true,
      cursorStyle: 'bar',
      scrollback: 10000,
      allowProposedApi: true,
    })

    const fit      = new FitAddon()
    const serialize = new SerializeAddon()

    term.loadAddon(fit)
    term.loadAddon(serialize)
    term.loadAddon(new Unicode11Addon())
    term.loadAddon(new WebLinksAddon())
    term.open(containerRef.current)

    requestAnimationFrame(() => {
      fit.fit()

      try {
        const webgl = new WebglAddon()
        webgl.onContextLoss(() => webgl.dispose())
        term.loadAddon(webgl)
      } catch (_) {}

      term.unicode.activeVersion = '11'

      termRef.current     = term
      fitRef.current      = fit
      serializeRef.current = serialize

      // Restore previous screen content instantly before WS connects
      if (resume && _session.snapshot) {
        term.write(_session.snapshot)
      }

      const ws = new WebSocket(termWsUrl(sid))
      ws.binaryType = 'arraybuffer'
      wsRef.current = ws

      ws.onopen = () => {
        setStatus('connected')
        ws.send(JSON.stringify({ type: 'resize', rows: term.rows, cols: term.cols }))
      }
      ws.onmessage = (e) => {
        term.write(e.data instanceof ArrayBuffer ? new Uint8Array(e.data) : e.data)
      }
      ws.onclose = () => setStatus('disconnected')
      ws.onerror = () => setStatus('error')

      term.onData((data) => {
        if (ws.readyState === WebSocket.OPEN) ws.send(new TextEncoder().encode(data))
      })

      const sendResize = () => {
        fit.fit()
        if (ws.readyState === WebSocket.OPEN)
          ws.send(JSON.stringify({ type: 'resize', rows: term.rows, cols: term.cols }))
      }

      const ro = new ResizeObserver(sendResize)
      ro.observe(containerRef.current)
      roRef.current = ro
    })
  }, [])

  useEffect(() => {
    const sid    = getOrCreateSessionId()
    const resume = !!_session.snapshot
    connect(sid, resume)

    return () => {
      // Save screen snapshot before unmounting
      if (serializeRef.current) _session.snapshot = serializeRef.current.serialize()
      roRef.current?.disconnect()
      wsRef.current?.close()
      termRef.current?.dispose()
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const handleNewSession = () => {
    _session.id       = null
    _session.snapshot = ''
    const sid = getOrCreateSessionId()
    connect(sid, false)
  }

  return (
    <div className="flex flex-col h-full bg-[#0d1117]" style={{ minHeight: 0 }}>
      {/* Toolbar */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-[#30363d] flex-shrink-0">
        <span className="text-[#58a6ff] font-bold text-sm tracking-wide">▸ Terminal</span>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className={`inline-block w-2 h-2 rounded-full ${STATUS_COLOR[status] || 'bg-gray-500'}`} />
            <span className="text-[10px] text-[#8b949e] font-mono">{status}</span>
          </div>
          <button
            onClick={handleNewSession}
            className="text-[11px] px-2 py-1 rounded bg-[#21262d] border border-[#30363d] text-[#8b949e] hover:text-[#e6edf3] hover:border-[#58a6ff] transition-colors"
          >
            + new session
          </button>
        </div>
      </div>

      {/* Terminal */}
      <div
        ref={containerRef}
        className="flex-1 overflow-hidden"
        style={{ minHeight: 0, padding: '6px 4px 4px 8px' }}
      />
    </div>
  )
}
