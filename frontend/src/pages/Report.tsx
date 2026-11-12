import '../styles/tables.css'
import '../styles/pages/report.css'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowRight, ChevronDown, ChevronRight, RefreshCw, Search, AlertTriangle } from 'lucide-react'
import type { Finding, Report as ReportData, Scan, Severity } from '../types'
import { api, ApiError, errorMessage, saveBlob } from '../lib/api'
import { exampleReport, exampleScan } from '../lib/examples'
import { duration, hostOf, normalizeFinding, profileLabel, relativeTime, SEVERITIES, severityCounts } from '../lib/format'
import { useWorkspace } from '../lib/store'
import { Button, EmptyState, SeverityLabel, StatusLabel } from '../components/Primitives'
import { FindingDrawer } from '../components/FindingDrawer'

function localFlags(id: string): string[] {
  try { const value: unknown = JSON.parse(localStorage.getItem(`wp.falsePositives.${id}`) || '[]'); return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [] } catch { return [] }
}

export function ReportPage() {
  const { id = '' } = useParams()
  const { toast } = useWorkspace()
  const [scan, setScan] = useState<Scan | null>(null)
  const [report, setReport] = useState<ReportData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState<Severity | 'all'>('all')
  const [phase, setPhase] = useState('all')
  const [sort, setSort] = useState('desc')
  const [selected, setSelected] = useState<Finding | null>(null)
  const [flags, setFlags] = useState<string[]>(() => localFlags(id))
  const sample = exampleScan(id)

  const load = useCallback(async () => {
    setLoading(true); setError('')
    try {
      if (sample) {
        const data = exampleReport(id)
        if (!data) throw new Error('No report is available for this example scan.')
        setScan(sample); setReport(data)
      } else {
        const [scanResult, reportResult] = await Promise.allSettled([api.scan(id), api.report(id)])
        if (reportResult.status === 'rejected') throw reportResult.reason
        const reportData = reportResult.value
        if (scanResult.status === 'fulfilled') setScan(scanResult.value)
        else if (scanResult.reason instanceof ApiError && scanResult.reason.status === 404) {
          // The in-memory registry can be lost after a restart while a report
          // still exists on disk or in R2. Do not invent its status or date.
          setScan({ scan_id: id, url: reportData.metadata?.target || '', profile: reportData.metadata?.profile || '', status: 'unknown', created_at: 0, duration_seconds: reportData.metadata?.duration_seconds, findings_count: reportData.findings.length })
        } else throw scanResult.reason
        setReport(reportData)
      }
    } catch (caught) { setError(errorMessage(caught)) } finally { setLoading(false) }
  }, [id, sample])
  useEffect(() => { setFlags(localFlags(id)); void load() }, [id, load])

  const findings = useMemo(() => (report?.findings || []).map(normalizeFinding), [report])
  const counts = useMemo(() => severityCounts(findings), [findings])
  const filtered = useMemo(() => findings.filter((finding) => {
    const haystack = `${finding.title} ${finding.url} ${finding.endpoint} ${finding.parameter} ${finding.cwe}`.toLowerCase()
    return haystack.includes(query.toLowerCase().trim()) && (severity === 'all' || finding.severity === severity) && (phase === 'all' || finding.phase === phase)
  }).sort((a, b) => {
    if (a.score === null && b.score === null) return 0
    if (a.score === null) return 1
    if (b.score === null) return -1
    return sort === 'asc' ? a.score - b.score : b.score - a.score
  }), [findings, query, severity, phase, sort])
  const maxScore = findings.reduce<number | null>((max, item) => item.score === null ? max : max === null ? item.score : Math.max(max, item.score), null)
  const phases = Array.from(new Set(findings.map((finding) => finding.phase).filter(Boolean)))
  const clear = () => { setQuery(''); setSeverity('all'); setPhase('all') }

  function toggleFalsePositive() {
    if (!selected) return
    const next = flags.includes(selected.id) ? flags.filter((flag) => flag !== selected.id) : [...flags, selected.id]
    setFlags(next)
    try { localStorage.setItem(`wp.falsePositives.${id}`, JSON.stringify(next)) } catch { toast('Could not save this annotation in your browser.', 'error'); return }
    toast(next.includes(selected.id) ? 'Marked as a false positive in this browser.' : 'False positive mark removed.', 'success')
  }

  async function download(format: 'json' | 'md' | 'sarif') {
    try {
      if (sample && report) {
        if (format === 'sarif') { toast('SARIF export is available for real assessments.', 'info'); return }
        const content = format === 'json' ? JSON.stringify(report, null, 2) : `# Example WebProbe report\n\nTarget: ${scan?.url}\n\n${findings.map((item) => `## [${item.severity.toUpperCase()}] ${item.title}\n\n${item.evidence}\n\nRemediation: ${item.remediation}\n`).join('\n')}`
        saveBlob(new Blob([content], { type: format === 'json' ? 'application/json' : 'text/markdown' }), `webprobe-example.${format}`)
      } else await api.download(id, format)
      toast(`${format === 'md' ? 'Markdown' : format.toUpperCase()} export started.`, 'success')
    } catch (caught) { toast(errorMessage(caught), 'error') }
  }

  if (loading) return <div className="page standard-page"><div className="loading-copy"><span className="spinner-inline" />Loading report...</div></div>
  if (error || !scan || !report) return <div className="page standard-page"><EmptyState title="Couldn't load report." description={error || 'The report is unavailable.'} action={<><Button onClick={() => void load()}>Retry</Button><Link to="/scans" className="button button-ghost">Back to scans</Link></>} /></div>
  const rerun = `/scans/new?url=${encodeURIComponent(scan.url)}&profile=${encodeURIComponent(scan.profile)}`

  return <div className="page standard-page report-page">
    <div className="report-heading"><div><div className="eyebrow page-eyebrow">{sample ? 'EXAMPLE REPORT' : 'ASSESSMENT REPORT'} <span className="eyebrow-slash">/</span> {id.startsWith('example-') ? 'SAMPLE' : id.slice(0, 8).toUpperCase()}</div><div className="report-title-line"><h1 className="report-target mono" title={scan.url}>{hostOf(scan.url)}</h1><StatusLabel status={scan.status} /></div><p>{scan.profile ? `${profileLabel(scan.profile)} profile` : 'Profile unavailable'} <span>·</span> {scan.created_at ? `Started ${relativeTime(scan.created_at)}` : 'Start time unavailable'}{report.metadata?.engines && report.metadata.engines.length > 0 && <> <span>·</span> Engines: <span className="mono">{report.metadata.engines.join(', ')}</span></>}</p></div>
      <div className="report-actions"><Link className="button button-secondary" to={rerun}><RefreshCw size={14} /> Re-run</Link><details className="export-menu"><summary className="button button-secondary">Export <ChevronDown size={14} /></summary><div className="export-options"><button onClick={() => void download('json')}>JSON <span>.json</span></button><button onClick={() => void download('md')}>Markdown <span>.md</span></button><button onClick={() => void download('sarif')}>SARIF <span>.sarif</span></button></div></details></div>
    </div>
    {sample && <div className="example-notice report-example"><span className="example-square" /><span>This is an example report, not a real assessment.</span></div>}
    {(report.metadata?.partial || scan.partial || report.metadata?.fallback || scan.fallback) && (
      <div className="example-notice report-notice-banner" role="alert" style={{ background: 'rgba(234, 179, 8, 0.12)', borderColor: '#eab308', color: '#fde047', padding: '12px 16px', borderRadius: '6px', margin: '16px 0', display: 'flex', alignItems: 'center', gap: '10px' }}>
        <AlertTriangle size={18} style={{ color: '#eab308', flexShrink: 0 }} />
        <div>
          {report.metadata?.fallback || scan.fallback ? (
            <span><strong>Notice: </strong>Scan ran in fallback mode ({report.metadata?.note || scan.note || 'Full engines were asleep; ran WebProbe only'}). Engines that did not run: kagesec, openosint.</span>
          ) : (
            <span>
              <strong>Partial assessment: </strong>
              {report.metadata?.note || scan.note || 'Some engines did not complete successfully.'}
              {(() => {
                const breakdown = report.metadata?.engines_breakdown || report.metadata?.engine_breakdown
                let didNotRun: string[] = []
                if (breakdown) {
                  didNotRun = Object.entries(breakdown).filter(([_, info]) => !info?.succeeded).map(([name]) => name)
                } else if (report.metadata?.engine === 'all') {
                  const ran = new Set(report.metadata?.engines || [])
                  didNotRun = ['webprobe', 'kagesec', 'openosint'].filter((e) => !ran.has(e))
                }
                return didNotRun.length > 0 ? ` Engines that did not run: ${didNotRun.join(', ')}.` : ''
              })()}
            </span>
          )}
        </div>
      </div>
    )}
    <section className="report-summary major-section" aria-label="Report summary">
      <div className="section-prelude"><span className="eyebrow">ASSESSMENT SUMMARY</span><span className="report-summary-id mono">{sample ? 'EXAMPLE DATA' : id.slice(0, 8)}</span></div>
      <div className="summary-values"><div><strong className="mono">{maxScore === null ? '—' : maxScore.toFixed(1)}</strong><span>max CVSS</span></div><i>·</i><div><strong className="mono">{findings.length}</strong><span>findings</span></div><i>·</i><div><strong className="mono">{duration(scan.duration_seconds ?? report.metadata?.duration_seconds)}</strong><span>duration</span></div></div>
      <div className="severity-meter" role="img" aria-label={`Findings by severity: ${SEVERITIES.map((level) => `${level} ${counts[level]}`).join(', ')}`}>{SEVERITIES.map((level) => counts[level] > 0 && <span key={level} className={`meter-${level} ${severity !== 'all' && severity !== level ? 'meter-faded' : ''}`} style={{ width: `${counts[level] / Math.max(findings.length, 1) * 100}%` }} />)}{findings.length === 0 && <span className="meter-empty" />}</div>
      <div className="severity-legend">{SEVERITIES.map((level) => <button key={level} className={severity === level ? 'legend-active' : ''} aria-pressed={severity === level} onClick={() => setSeverity((current) => current === level ? 'all' : level)}><span className={`dot dot-${level}`} /><span>{level.charAt(0).toUpperCase() + level.slice(1)}</span><strong>{counts[level]}</strong></button>)}</div>
    </section>
    <section className="findings-section major-section" aria-labelledby="findings-title"><div className="section-heading findings-heading"><div><h2 id="findings-title">Findings</h2><p>Review and investigate the results of this assessment.</p></div><span className="result-count">{filtered.length} OF {findings.length}</span></div>
      <div className="filter-row findings-filters"><label className="search-field"><Search size={15} /><span className="sr-only">Search findings</span><input placeholder="Search findings..." value={query} onChange={(event) => setQuery(event.target.value)} /></label><label className="select-wrap"><span className="sr-only">Filter by phase</span><select value={phase} onChange={(event) => setPhase(event.target.value)}><option value="all">Phase: All</option>{phases.map((item) => <option value={item} key={item}>{item}</option>)}</select></label><label className="select-wrap"><span className="sr-only">Sort by CVSS</span><select value={sort} onChange={(event) => setSort(event.target.value)}><option value="desc">CVSS: High to low</option><option value="asc">CVSS: Low to high</option></select></label></div>
      {filtered.length ? <div className="table-scroll"><table className="data-table findings-table"><caption className="sr-only">Assessment findings</caption><thead><tr><th scope="col">Severity</th><th scope="col">Title</th><th scope="col">Endpoint</th><th scope="col">CVSS</th><th scope="col"><span className="sr-only">Inspect</span></th></tr></thead><tbody>{filtered.map((finding) => <tr key={finding.id} className={`finding-row finding-row-${finding.severity}`} tabIndex={0} onClick={() => setSelected(finding)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelected(finding) } }} aria-label={`Inspect ${finding.title}`}><td><SeverityLabel severity={finding.severity} /></td><td><span className="finding-title">{finding.title}</span>{flags.includes(finding.id) && <span className="flag-label">False positive · local</span>}</td><td className="mono finding-endpoint" title={finding.url}>{finding.method && <span>{finding.method} </span>}{finding.endpoint}</td><td className="mono finding-score">{finding.score === null ? '—' : finding.score.toFixed(1)}</td><td className="action-cell"><ChevronRight size={14} /></td></tr>)}</tbody></table></div> : <EmptyState title={findings.length ? 'No findings match your filters.' : 'No findings detected.'} description={findings.length ? 'Clear the filters to see all findings.' : 'You can run another assessment to review this target again.'} action={findings.length ? <Button onClick={clear}>Clear filters</Button> : <Link className="button button-secondary" to={rerun}>Re-run assessment <ArrowRight size={14} /></Link>} />}
      <div className="table-footer"><span>FINDINGS</span><span>END OF RESULTS</span></div>
    </section>
    {selected && <FindingDrawer key={selected.id} finding={selected} isFalsePositive={flags.includes(selected.id)} toggleFalsePositive={toggleFalsePositive} close={() => setSelected(null)} />}
  </div>
}
