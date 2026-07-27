export const SEV_COLOR = {
  critical: '#ff4444',
  high:     '#f85149',
  medium:   '#f0b429',
  low:      '#58a6ff',
  info:     '#8b949e',
  unknown:  '#8b949e',
}
export const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown']

export default function SevBadge({ sev }) {
  const s = (sev || 'unknown').toLowerCase()
  const c = SEV_COLOR[s] ?? SEV_COLOR.unknown
  return (
    <span
      style={{ color: c, borderColor: c + '55', background: c + '18' }}
      className="text-[10px] font-mono border rounded px-1.5 py-0.5 uppercase tracking-wide whitespace-nowrap"
    >
      {s}
    </span>
  )
}
