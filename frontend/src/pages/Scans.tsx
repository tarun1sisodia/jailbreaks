import '../styles/pages/scans.css'
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Plus, Search } from 'lucide-react'
import { ScanTable } from '../components/ScanTable'
import { Button, EmptyState } from '../components/Primitives'
import { useWorkspace } from '../lib/store'

export function Scans() {
  const { visibleScans, scansError, refreshScans } = useWorkspace()
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState('all')
  const [profile, setProfile] = useState('all')
  const matches = useMemo(() => visibleScans.filter((scan) => {
    const text = `${scan.url} ${scan.scan_id}`.toLowerCase()
    return text.includes(query.toLowerCase().trim()) && (status === 'all' || scan.status === status || (status === 'failed' && scan.status === 'error')) && (profile === 'all' || scan.profile === profile)
  }), [visibleScans, query, status, profile])
  function clear() { setQuery(''); setStatus('all'); setProfile('all') }
  return <div className="page standard-page">
    <div className="page-heading"><div><div className="eyebrow page-eyebrow">ASSESSMENTS / HISTORY</div><h1>Scans</h1><p>All assessments in this workspace.</p></div><Link className="button button-primary" to="/scans/new"><Plus size={15} /> New scan</Link></div>
    <div className="page-rule" />
    <div className="filter-row scan-filters">
      <label className="search-field"><Search size={15} /><span className="sr-only">Search scans</span><input placeholder="Search by target..." value={query} onChange={(event) => setQuery(event.target.value)} /></label>
      <label className="select-wrap"><span className="sr-only">Filter by status</span><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="all">Status: All</option><option value="running">Running</option><option value="queued">Queued</option><option value="completed">Completed</option><option value="failed">Failed</option><option value="aborted">Aborted</option></select></label>
      <label className="select-wrap"><span className="sr-only">Filter by profile</span><select value={profile} onChange={(event) => setProfile(event.target.value)}><option value="all">Profile: All</option>{Array.from(new Set(visibleScans.map((scan) => scan.profile))).map((value) => <option key={value} value={value}>{value.toUpperCase()}</option>)}</select></label>
      <span className="filter-count">{matches.length} {matches.length === 1 ? 'scan' : 'scans'}</span>
    </div>
    {scansError && <div className="inline-error">{scansError} <button onClick={() => void refreshScans()}>Retry</button></div>}
    {matches.length ? <ScanTable scans={matches} /> : <EmptyState title="No scans found." description="Start an assessment or clear filters to see your scans." action={<Button onClick={clear}>Clear filters</Button>} />}
    <div className="table-footer"><span>ASSESSMENTS</span><span>{matches.length} RESULTS</span></div>
  </div>
}
