import '../styles/tables.css'
import '../styles/pages/catalog.css'
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, Search } from 'lucide-react'
import { Button, EmptyState } from '../components/Primitives'
import { profileLabel } from '../lib/format'
import { useWorkspace } from '../lib/store'

function checkName(id: string) {
  const abbreviations: Record<string, string> = { jwt: 'JWT', csrf: 'CSRF', xss: 'XSS', sqli: 'SQLi', idor: 'IDOR', tls: 'TLS', cors: 'CORS', csp: 'CSP', ssrf: 'SSRF', api: 'API', rbac: 'RBAC', graphql: 'GraphQL', rce: 'RCE', oauth: 'OAuth', h2: 'HTTP/2', cve: 'CVE', js: 'JavaScript' }
  return id.split('_').map((word) => abbreviations[word] || word.charAt(0).toUpperCase() + word.slice(1)).join(' ')
}

export function Catalog() {
  const { health, profiles, refreshProfiles, refreshHealth } = useWorkspace()
  const [query, setQuery] = useState('')
  const [profile, setProfile] = useState('all')
  const checks = useMemo(() => {
    if (!profiles) return []
    const byId = new Map<string, string[]>()
    Object.entries(profiles).forEach(([name, data]) => data.checks.forEach((id) => byId.set(id, [...(byId.get(id) || []), name])))
    return Array.from(byId.entries()).map(([id, included]) => ({ id, name: checkName(id), included })).sort((a, b) => a.name.localeCompare(b.name))
  }, [profiles])
  const filtered = checks.filter((check) => `${check.id} ${check.name}`.toLowerCase().includes(query.toLowerCase().trim()) && (profile === 'all' || check.included.includes(profile)))
  return <div className="page standard-page catalog-page">
    <div className="page-heading"><div><div className="eyebrow page-eyebrow">ENGINE / COVERAGE</div><h1>Check catalog</h1><p>The checks available in the connected WebProbe engine.</p></div><Link to="/scans/new" className="button button-secondary">New assessment <ArrowRight size={14} /></Link></div>
    <div className="page-rule" />
    {!profiles ? <EmptyState title="Couldn't load the catalog." description="Connect to the backend to see available checks." action={<Button onClick={() => { void refreshProfiles(); void refreshHealth() }}>Retry connection</Button>} /> : <>
      <div className="catalog-summary"><div><span className="metric-label">REGISTERED CHECKS</span><strong className="mono">{health?.total_checks ?? checks.length}</strong></div><div><span className="metric-label">AVAILABLE PROFILES</span><strong className="mono">{Object.keys(profiles).length}</strong></div><p>Check names and profile coverage are supplied by the connected engine.</p></div>
      <div className="filter-row catalog-filters"><label className="search-field"><Search size={15} /><span className="sr-only">Search checks</span><input placeholder="Search checks..." value={query} onChange={(event) => setQuery(event.target.value)} /></label><label className="select-wrap"><span className="sr-only">Filter by profile</span><select value={profile} onChange={(event) => setProfile(event.target.value)}><option value="all">Profile: All</option>{Object.keys(profiles).map((value) => <option key={value} value={value}>{profileLabel(value)}</option>)}</select></label><span className="filter-count">{filtered.length} checks</span></div>
      {filtered.length ? <div className="table-scroll"><table className="data-table catalog-table"><caption className="sr-only">Available scanner checks</caption><thead><tr><th scope="col">Check</th><th scope="col">Identifier</th><th scope="col">Included in</th></tr></thead><tbody>{filtered.map((check) => <tr key={check.id}><td>{check.name}</td><td className="mono catalog-id">{check.id}</td><td className="catalog-profiles">{check.included.filter((item) => item !== 'full').map(profileLabel).join(' · ') || 'Full'}</td></tr>)}</tbody></table></div> : <EmptyState title="No checks match." description="Clear the filters to see available checks." action={<Button onClick={() => { setQuery(''); setProfile('all') }}>Clear filters</Button>} />}
      <div className="table-footer"><span>ENGINE CATALOG</span><span>{filtered.length} RESULTS</span></div>
    </>}
  </div>
}
