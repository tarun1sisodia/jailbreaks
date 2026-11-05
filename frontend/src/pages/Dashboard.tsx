import '../styles/pages/dashboard.css'
import { useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ArrowRight, Globe2, LoaderCircle } from 'lucide-react'
import type { ProfileId } from '../types'
import { api, errorMessage } from '../lib/api'
import { hostOf, validHttpUrl } from '../lib/format'
import { rememberScan, useWorkspace } from '../lib/store'
import { ScanTable } from '../components/ScanTable'

const QUICK_PROFILES: { id: ProfileId; label: string }[] = [
  { id: 'quick', label: 'Quick' }, { id: 'owasp', label: 'OWASP' }, { id: 'full', label: 'Full' }, { id: 'api', label: 'API' },
]

export function Dashboard() {
  const navigate = useNavigate()
  const { settings, visibleScans, showingExamples, scansError, refreshScans, toast } = useWorkspace()
  const [url, setUrl] = useState('')
  const [profile, setProfile] = useState<ProfileId>(() => {
    try {
      const last = sessionStorage.getItem('wp.lastProfile') as ProfileId | null
      return QUICK_PROFILES.some((item) => item.id === last) ? last! : QUICK_PROFILES.some((item) => item.id === settings.defaultProfile) ? settings.defaultProfile : 'quick'
    } catch { return settings.defaultProfile }
  })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const metrics = useMemo(() => {
    const finished = visibleScans.filter((scan) => scan.status === 'completed')
    return {
      total: visibleScans.length,
      severe: finished.reduce((total, scan) => total + (scan.severity_summary?.critical || 0) + (scan.severity_summary?.high || 0), 0),
      clean: new Set(finished.filter((scan) => scan.findings_count === 0).map((scan) => hostOf(scan.url))).size,
    }
  }, [visibleScans])

  async function start(event: FormEvent) {
    event.preventDefault()
    if (!validHttpUrl(url)) { setError('Enter a valid URL beginning with http:// or https://.'); return }
    setError('')
    setLoading(true)
    try {
      const result = await api.start(settings.apiBase, { url: url.trim(), profile, rate_limit: settings.rateLimit, aimd: settings.aimd, redact: settings.redact })
      rememberScan(result.scan_id)
      void refreshScans()
      toast('Assessment queued.', 'success')
      navigate(`/scans/${result.scan_id}`)
    } catch (caught) { setError(errorMessage(caught)) } finally { setLoading(false) }
  }

  return <div className="page dashboard-page">
    <section className="dashboard-hero" aria-labelledby="dashboard-title">
      <div className="eyebrow hero-eyebrow"><span className="eyebrow-line" />WEB SECURITY ASSESSMENTS</div>
      <h1 id="dashboard-title">Audit any endpoint in seconds.</h1>
      <p className="hero-copy">Paste a URL. Get CVSS-scored findings with verified evidence<br className="desktop-break" /> and clear remediation guidance.</p>
      <form className="hero-form" onSubmit={start} noValidate>
        <div className={`scan-input-shell ${error ? 'has-error' : ''}`}>
          <Globe2 size={17} strokeWidth={1.75} className="input-leading-icon" />
          <label className="sr-only" htmlFor="dashboard-url">Target URL</label>
          <input id="dashboard-url" type="url" inputMode="url" autoComplete="url" placeholder="https://your-domain.com" value={url} onChange={(event) => { setUrl(event.target.value); if (error) setError('') }} />
          <button type="submit" className="assess-button" disabled={loading}>{loading && <LoaderCircle size={14} className="spinner" />}<span>Assess</span>{!loading && <ArrowRight size={15} />}</button>
        </div>
        {error && <p className="input-error" role="alert">{error}</p>}
        <div className="hero-options">
          <div className="profile-selector" aria-label="Scan profile">
            <span className="profile-prefix">PROFILE</span>
            {QUICK_PROFILES.map((item, index) => <span className="profile-option" key={item.id}>{index > 0 && <span className="option-separator">·</span>}<button type="button" className={profile === item.id ? 'profile-active' : ''} aria-pressed={profile === item.id} onClick={() => { setProfile(item.id); try { sessionStorage.setItem('wp.lastProfile', item.id) } catch { /* Optional preference. */ } }}>{item.label}</button></span>)}
          </div>
          <Link className="advanced-link" to={`/scans/new${url ? `?url=${encodeURIComponent(url)}&profile=${profile}` : `?profile=${profile}`}`}>Advanced configuration <ArrowRight size={13} /></Link>
        </div>
      </form>
      <p className="authorization-note">Only assess targets you own or have permission to test.</p>
    </section>

    <section className="dashboard-metrics major-section" aria-label="Assessment overview">
      <div className="section-prelude"><span className="eyebrow">WORKSPACE OVERVIEW</span>{showingExamples && <span className="example-caption"><span className="example-square" />EXAMPLE DATA</span>}</div>
      <div className="metric-strip">
        <div className="metric"><span className="metric-label">TOTAL SCANS</span><strong className="metric-value">{String(metrics.total).padStart(2, '0')}</strong></div>
        <div className="metric"><span className="metric-label">CRITICAL &amp; HIGH</span><strong className={`metric-value ${metrics.severe ? 'metric-alert' : ''}`}>{String(metrics.severe).padStart(2, '0')}</strong></div>
        <div className="metric"><span className="metric-label">CLEAN ENDPOINTS</span><strong className="metric-value">{String(metrics.clean).padStart(2, '0')}</strong></div>
      </div>
    </section>

    <section className="recent-section major-section" aria-labelledby="recent-title">
      <div className="section-heading"><div><h2 id="recent-title">Recent scans</h2></div><Link to="/scans" className="text-link">View all scans <ArrowRight size={14} /></Link></div>
      {showingExamples && <div className="example-notice"><span className="example-square" /><span>Showing example scans. Your assessments will appear here.</span></div>}
      {scansError && <div className="inline-error">{scansError} <button onClick={() => void refreshScans()}>Retry</button></div>}
      <ScanTable scans={visibleScans.slice(0, 5)} />
      <div className="table-footer"><span>{showingExamples ? 'EXAMPLE WORKSPACE' : `${visibleScans.length} ${visibleScans.length === 1 ? 'ASSESSMENT' : 'ASSESSMENTS'}`}</span><span>END OF RESULTS</span></div>
    </section>
  </div>
}
