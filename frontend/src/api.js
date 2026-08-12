const BASE = '/api/v1'

async function req(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || res.statusText)
  }
  if (res.status === 204) return null
  return res.json()
}

export const api = {
  // Workflows
  getWorkflows:   () => req('GET', '/workflows'),
  getWorkflow:    (name) => req('GET', `/workflows/${encodeURIComponent(name)}`),
  saveWorkflow:   (name, body) => req('PUT', `/workflows/${encodeURIComponent(name)}`, body),
  deleteWorkflow: (name) => req('DELETE', `/workflows/${encodeURIComponent(name)}`),

  // Runs
  getRuns: (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null)).toString()
    return req('GET', `/runs${qs ? '?' + qs : ''}`)
  },
  getStats: () => req('GET', '/runs/stats'),
  getRun: (id) => req('GET', `/runs/${id}`),
  createRun: (body) => req('POST', '/runs', body),
  cancelRun: (id) => req('POST', `/runs/${id}/cancel`),
  pauseRun:       (id) => req('POST',   `/runs/${id}/pause`),
  cancelPause:    (id) => req('DELETE', `/runs/${id}/pause`),
  resumeRun:      (id) => req('POST',   `/runs/${id}/resume`),
  deleteRun: (id) => req('DELETE', `/runs/${id}`),

  // Logs (paginated)
  getLogs: (id, params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null)).toString()
    return req('GET', `/runs/${id}/logs${qs ? '?' + qs : ''}`)
  },

  // Files
  getFiles: (runId) => req('GET', `/runs/${runId}/files`),
  getScreenshots: (runId) => req('GET', `/runs/${runId}/screenshots`),
  getFileContent: (runId, path) =>
    fetch(`${BASE}/runs/${runId}/files/${path.split('/').map(encodeURIComponent).join('/')}`).then(r => r.text()),

  // Findings
  getFindings: (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null)).toString()
    return req('GET', `/findings${qs ? '?' + qs : ''}`)
  },
  getFindingsStats: () => req('GET', '/findings/stats'),
  getRunFindings: (runId, params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null)).toString()
    return req('GET', `/runs/${runId}/findings${qs ? '?' + qs : ''}`)
  },
  patchFinding: (id, body) => req('PATCH', `/findings/${id}`, body),
  reparseFinding: (runId) => req('POST', `/runs/${runId}/findings/reparse`),

  // Reports
  reportUrl: (runId) => `${BASE}/runs/${runId}/report`,

  // Tools
  getTools: () => req('GET', '/tools'),
  checkToolVersions: () => req('POST', '/tools/check'),
  updateTools: (body = {}) => req('POST', '/tools/update', body),

  // Asset Inventory (cross-run deduped http findings)
  getAssets: (params = {}) => {
    const entries = []
    for (const [k, v] of Object.entries(params)) {
      if (Array.isArray(v)) v.forEach(x => entries.push([k, x]))
      else if (v != null) entries.push([k, v])
    }
    const s = new URLSearchParams(entries).toString()
    return req('GET', `/assets${s ? '?' + s : ''}`)
  },
  getAssetsStats: () => req('GET', '/assets/stats'),
  deleteAsset: (host, port) => req('DELETE', '/assets', { host, port: port ?? null }),

  // API Keys
  getKeys:      () => req('GET', '/keys'),
  getKeysStats: () => req('GET', '/keys/stats'),
  getEnvStatus: () => req('GET', '/keys/env-status'),
  setKey:       (provider, value) => req('PUT', `/keys/${provider}`, { value }),
  deleteKey:    (provider) => req('DELETE', `/keys/${provider}`),
}

export function wsUrl(runId) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${location.host}/ws/runs/${runId}`
}
