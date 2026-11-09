import '../styles/tables.css'
import '../styles/components/scan-table.css'
import { ChevronRight } from 'lucide-react'
import { Link, useNavigate } from 'react-router-dom'
import type { Scan } from '../types'
import { hostOf, profileLabel, relativeTime, scanDuration } from '../lib/format'
import { StatusLabel } from './Primitives'

export function scanPath(scan: Scan): string {
  return `/scans/${encodeURIComponent(scan.scan_id)}${scan.status === 'completed' ? '/report' : ''}`
}

function FindingCount({ scan }: { scan: Scan }) {
  if (scan.status !== 'completed') return <span className="muted-dash">—</span>
  const critical = scan.severity_summary?.critical || 0
  const high = scan.severity_summary?.high || 0
  if (critical || high) return <span className="finding-counts">
    {critical > 0 && <span><span className="dot dot-critical" />{critical} <span className="count-label">Critical</span></span>}
    {high > 0 && <span><span className="dot dot-high" />{high} <span className="count-label">High</span></span>}
  </span>
  if (scan.findings_count) return <span className="finding-neutral">{scan.findings_count} findings</span>
  return <span className="finding-neutral">No findings</span>
}

export function ScanTable({ scans }: { scans: Scan[] }) {
  const navigate = useNavigate()
  return <div className="table-scroll"><table className="data-table scan-table">
    <caption className="sr-only">Assessment scans</caption>
    <thead><tr><th scope="col">Target</th><th scope="col">Profile</th><th scope="col">Status</th><th scope="col">Findings</th><th scope="col">Duration</th><th scope="col">Started</th><th scope="col"><span className="sr-only">Open</span></th></tr></thead>
    <tbody>
      {scans.length === 0 ? (
        <tr>
          <td colSpan={7} style={{ textAlign: 'center', padding: '2.5rem 1rem', color: 'var(--text-muted, #71717a)' }}>
            No assessments yet. Enter a target above to begin scanning.
          </td>
        </tr>
      ) : (
        scans.map((scan) => <tr key={scan.scan_id} className="scan-row" onClick={() => navigate(scanPath(scan))}>
          <td><Link to={scanPath(scan)} onClick={(event) => event.stopPropagation()} className="target-link mono" title={scan.url}>{hostOf(scan.url)}</Link></td>
          <td className="profile-cell">{profileLabel(scan.profile)}</td>
          <td><StatusLabel status={scan.status} /></td>
          <td><FindingCount scan={scan} /></td>
          <td className="mono time-cell">{scanDuration(scan)}</td>
          <td className="time-cell" title={new Date(scan.created_at * 1000).toLocaleString()}>{relativeTime(scan.created_at)}</td>
          <td className="action-cell"><ChevronRight size={14} /></td>
        </tr>)
      )}
    </tbody>
  </table></div>
}
