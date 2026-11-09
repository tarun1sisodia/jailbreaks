import '../styles/pages/console.css'
import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowRight, ExternalLink, RefreshCw } from 'lucide-react'
import type { Scan } from '../types'
import { api, errorMessage } from '../lib/api'
import { EXAMPLE_FAILED_LOG, EXAMPLE_LOG, exampleScan } from '../lib/examples'
import { hostOf, profileLabel, safeExternalUrl, scanDuration } from '../lib/format'
import { useWorkspace } from '../lib/store'
import { Button, ConfirmDialog, EmptyState, StatusLabel } from '../components/Primitives'

const steps = ['Recon', 'Auth', 'Inject', 'Authz', 'Logic', 'Infra']
const ansi = /\u001b\[[0-9;]*m/g

export function ConsolePage() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const { toast, refreshScans } = useWorkspace()
  const sample = exampleScan(id)
  const [scan, setScan] = useState<Scan | null>(sample || null)
  const [log, setLog] = useState(sample ? (sample.status === 'failed' ? EXAMPLE_FAILED_LOG : EXAMPLE_LOG) : '')
  const [error, setError] = useState('')
  const [logError, setLogError] = useState('')
  const [loading, setLoading] = useState(!sample)
  const [autoscroll, setAutoscroll] = useState(true)
  const [abortOpen, setAbortOpen] = useState(false)
  const [aborting, setAborting] = useState(false)
  const [now, setNow] = useState(Date.now())
  const terminalRef = useRef<HTMLDivElement>(null)
  const redirected = useRef(false)
  const redirectTimer = useRef<number | undefined>()

  const refresh = useCallback(async () => {
    if (sample) return
    try {
      const next = await api.scan(id)
      setScan(next); setError('')
      if (next.status === 'completed' && !redirected.current) {
        redirected.current = true
        redirectTimer.current = window.setTimeout(() => navigate(`/scans/${id}/report`, { replace: true }), 1500)
        void refreshScans()
      }
    } catch (caught) { setError(errorMessage(caught)) } finally { setLoading(false) }
    try { setLog(await api.log(id)); setLogError('') } catch (caught) { setLogError(errorMessage(caught)) }
  }, [id, navigate, refreshScans, sample])

  useEffect(() => {
    setScan(sample || null)
    setLog(sample ? (sample.status === 'failed' ? EXAMPLE_FAILED_LOG : EXAMPLE_LOG) : '')
    setLoading(!sample)
    setLogError('')
    window.clearTimeout(redirectTimer.current)
    redirected.current = false
  }, [id, sample])
  useEffect(() => {
    void refresh()
    if (sample) return
    const active = !scan || scan.status === 'queued' || scan.status === 'running'
    const interval = window.setInterval(() => { void refresh() }, active ? 2500 : 30000)
    return () => window.clearInterval(interval)
  }, [refresh, sample, scan?.status])
  useEffect(() => () => { window.clearTimeout(redirectTimer.current) }, [])
  useEffect(() => { const interval = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(interval) }, [])
  useEffect(() => { if (autoscroll && terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight }, [log, autoscroll])

  async function abort() {
    setAborting(true)
    try {
      await api.abort(id)
      toast('Assessment aborted.', 'info')
      setAbortOpen(false)
      await refresh()
      void refreshScans()
    } catch (caught) { toast(errorMessage(caught), 'error'); await refresh() } finally { setAborting(false) }
  }
  async function copyLog() {
    try { await navigator.clipboard.writeText(log.replace(ansi, '')); toast('Log copied to clipboard.', 'success') } catch { toast('Could not copy log.', 'error') }
  }

  if (loading) return <div className="page standard-page"><div className="loading-copy"><span className="spinner-inline" />Connecting to scan...</div></div>
  if (!scan) return <div className="page standard-page"><EmptyState title="Couldn't load scan." description={error || 'This scan could not be found.'} action={<><Button onClick={() => void refresh()}>Retry</Button><Link className="button button-ghost" to="/scans">Back to scans</Link></>} /></div>
  const target = safeExternalUrl(scan.url)
  const running = scan.status === 'running' || scan.status === 'queued'
  const rerun = `/scans/new?url=${encodeURIComponent(scan.url)}&profile=${encodeURIComponent(scan.profile)}`
  const lines = log.replace(ansi, '').split('\n')

  return <div className="page standard-page console-page">
    <div className="eyebrow page-eyebrow">{sample ? 'EXAMPLE ASSESSMENT' : 'ASSESSMENT CONSOLE'} <span className="eyebrow-slash">/</span> {sample ? 'SAMPLE' : id.slice(0, 8).toUpperCase()}</div>
    <div className="console-heading"><div><h1>Scan console</h1><p>Assessment activity and scanner output.</p></div><div className="console-actions">{scan.status === 'completed' && <Link to={`/scans/${id}/report`} className="button button-secondary">View report <ArrowRight size={14} /></Link>}{!running && scan.status !== 'completed' && <Link to={rerun} className="button button-secondary"><RefreshCw size={14} /> Re-run</Link>}{running && !sample && <button className="abort-link" onClick={() => setAbortOpen(true)}>Abort scan</button>}</div></div>
    {sample && <div className="example-notice console-example"><span className="example-square" /><span>This is an example scan. No assessment is running.</span></div>}
    {error && <div className="inline-error">{error} <button onClick={() => void refresh()}>Retry</button></div>}
    <section className="console-status major-section"><div className="console-status-line"><StatusLabel status={scan.status} /><span className="console-separator">/</span>{target ? <a href={target} target="_blank" rel="noreferrer" className="console-target mono" title={scan.url}>{hostOf(scan.url)} <ExternalLink size={12} /></a> : <span className="console-target mono">{hostOf(scan.url)}</span>}<span className="console-status-spacer" /><span className="mono console-duration">{scanDuration(scan, now)}</span><span className="console-profile">{profileLabel(scan.profile)}</span></div>
      <div className="stepper-heading"><span className="eyebrow">ASSESSMENT PHASES</span><span>{sample ? 'Example progress' : 'Phase progress not reported by engine'}</span></div>
      <div className="stepper">{steps.map((step, index) => <div className="step" key={step}><span>{step}</span><div className="step-track"><i className={sample && scan.status === 'running' ? index < 3 ? 'step-done' : index === 3 ? 'step-active' : '' : ''} /></div></div>)}</div>
      <div className="console-metrics"><span><strong className="mono">{scanDuration(scan, now)}</strong> elapsed</span><span className="metric-divider">·</span><span>{running ? 'Findings available after completion' : <><strong className="mono">{scan.findings_count ?? '—'}</strong> findings</>}</span></div>
    </section>
    <section className="terminal-section"><div className="terminal-heading"><div><h2>Output</h2><p>Scanner activity in chronological order.</p></div><span className="terminal-live">{running && !sample ? 'LIVE OUTPUT' : sample ? 'EXAMPLE OUTPUT' : 'SCAN OUTPUT'}</span></div>
      <div className="terminal-frame"><button className={`autoscroll ${autoscroll ? 'on' : ''}`} onClick={() => setAutoscroll(!autoscroll)} aria-pressed={autoscroll}>auto-scroll {autoscroll ? 'on' : 'off'}</button><div className="terminal-scroll" ref={terminalRef} role="log" aria-label="Scanner output">{log ? lines.map((line, index) => <div key={index} className={`terminal-line ${/\[error\]|\[!\]/i.test(line) ? 'line-error' : /\[\+\]/.test(line) ? 'line-success' : ''}`}>{line || '\u00a0'}</div>) : <div className="terminal-placeholder">{logError ? 'Output unavailable.' : 'Waiting for scanner output...'}</div>}</div></div>
      <div className="terminal-foot"><span>{logError && !sample ? `${logError} ` : running && !sample ? 'Updates automatically while the assessment is active.' : 'Output from this assessment.'}</span><button className="subtle-link" disabled={!log} onClick={() => void copyLog()}>Copy log</button></div>
      {(scan.status === 'failed' || scan.status === 'error') && <div className="scan-failure"><span className="dot dot-critical" /><div><strong>Scan failed.</strong><p>{scan.error || (scan.exit_code !== undefined ? `The scanner exited with code ${scan.exit_code}.` : 'Review the output before re-running the assessment.')}</p></div></div>}
      {scan.status === 'aborted' && <div className="scan-failure"><span className="dot dot-info" /><div><strong>Scan aborted.</strong><p>A partial report may not be available.</p></div></div>}
    </section>
    {abortOpen && <ConfirmDialog title="Abort this scan?" description="The scanner will stop. A partial report may not be saved." confirmLabel="Abort scan" onClose={() => setAbortOpen(false)} onConfirm={() => void abort()} loading={aborting} />}
  </div>
}
