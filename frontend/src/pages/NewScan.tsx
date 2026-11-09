import '../styles/pages/new-scan.css'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { ArrowRight, ChevronDown, ShieldCheck } from 'lucide-react'
import type { EngineId, ProfileId } from '../types'
import { api, errorMessage } from '../lib/api'
import { profileLabel, validHttpUrl } from '../lib/format'
import { rememberScan, useWorkspace } from '../lib/store'
import { Button, Toggle } from '../components/Primitives'

const PROFILE_ORDER: ProfileId[] = ['quick', 'owasp', 'full', 'api', 'recon', 'auth']
const PROFILE_DESCRIPTIONS: Partial<Record<ProfileId, string>> = {
  quick: 'A focused smoke test for common issues.',
  owasp: 'Checks mapped to common web application risks.',
  full: 'All available checks across the assessment.',
  api: 'Focused on REST and GraphQL API security.',
  recon: 'Discover endpoints and exposed resources.',
  auth: 'Review authentication and session behavior.',
}

export function NewScan() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const { settings, profiles, engines, refreshScans, toast } = useWorkspace()
  const initialProfile = params.get('profile') as ProfileId | null
  const [url, setUrl] = useState(params.get('url') || '')
  const [repo, setRepo] = useState(params.get('repo') || '')
  const [engine, setEngine] = useState<EngineId>('webprobe')
  const [profile, setProfile] = useState<ProfileId>(initialProfile && PROFILE_ORDER.includes(initialProfile) ? initialProfile : settings.defaultProfile)
  const [rateLimit, setRateLimit] = useState(settings.rateLimit)
  const [aimd, setAimd] = useState(settings.aimd)
  const [redact, setRedact] = useState(settings.redact)
  const [cookie, setCookie] = useState('')
  const [secondaryCookie, setSecondaryCookie] = useState('')
  const [adminCookie, setAdminCookie] = useState('')
  const [webhook, setWebhook] = useState('')
  const [urlError, setUrlError] = useState('')
  const [submitError, setSubmitError] = useState('')
  const [loading, setLoading] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (engine === 'argus') {
      if (!repo.trim()) { setUrlError('Enter a git URL or a directory path on the server.'); return }
    } else if (!validHttpUrl(url)) { setUrlError('Enter a valid URL beginning with http:// or https://.'); return }
    if (webhook && !validHttpUrl(webhook)) { setSubmitError('Enter a valid webhook URL.'); return }
    setUrlError(''); setSubmitError(''); setLoading(true)
    try {
      const result = await api.start({
        url: engine === 'argus' ? '' : url.trim(), repo: repo.trim() || undefined, profile, engine, rate_limit: rateLimit, aimd, redact,
        cookie, secondary_cookie: secondaryCookie, admin_cookie: adminCookie,
        webhook_callback: webhook.trim() || null,
      })
      rememberScan(result.scan_id)
      void refreshScans()
      if (result.fallback) toast(result.note || 'Full engines were asleep; ran WebProbe only.', 'info')
      else toast('Assessment queued.', 'success')
      navigate(`/scans/${result.scan_id}`)
    } catch (error) { setSubmitError(errorMessage(error)) } finally { setLoading(false) }
  }

  return <div className="page standard-page setup-page">
    <div className="page-heading"><div><div className="eyebrow page-eyebrow">ASSESSMENTS / NEW SCAN</div><h1>Configure assessment</h1><p>Set a target and choose how WebProbe should assess it.</p></div></div>
    <div className="page-rule" />
    <form onSubmit={submit} noValidate>
      <div className="setup-layout">
        <div className="setup-main">
          <section className="form-section"><div className="form-section-title"><span>01</span><h2>Target</h2></div>
            {engine === 'argus'
              ? <div className="form-field"><label htmlFor="target-repo">Code repo</label><input id="target-repo" className={`text-input ${urlError ? 'input-invalid' : ''}`} type="text" placeholder="https://github.com/org/repo or /path/on/server" value={repo} onChange={(event) => { setRepo(event.target.value); setUrlError('') }} autoComplete="off" />{urlError ? <p className="input-error" role="alert">{urlError}</p> : <p className="field-hint">A git URL is cloned shallow on the server; a path must already exist on the server. Only scan code you own or are authorized to test.</p>}</div>
              : <div className="form-field"><label htmlFor="target-url">Target URL</label><input id="target-url" className={`text-input ${urlError ? 'input-invalid' : ''}`} type="url" placeholder="https://app.example.com" value={url} onChange={(event) => { setUrl(event.target.value); setUrlError('') }} autoComplete="url" />{urlError ? <p className="input-error" role="alert">{urlError}</p> : <p className="field-hint">Include http:// or https://.</p>}</div>}
            {engine === 'all' && <div className="form-field"><label htmlFor="target-repo-all">Code repo <span className="optional-label">OPTIONAL</span></label><input id="target-repo-all" className="text-input" type="text" placeholder="https://github.com/org/repo or /path/on/server" value={repo} onChange={(event) => setRepo(event.target.value)} autoComplete="off" /><p className="field-hint">Add a repo to also run Argus code scanning in this run.</p></div>}
          </section>
          <section className="form-section"><div className="form-section-title"><span>02</span><h2>Scan engine</h2></div>
            <div className="form-field"><label htmlFor="scan-engine">Engine</label><select id="scan-engine" className="text-input" value={engine} onChange={(event) => setEngine(event.target.value as EngineId)}>
              <option value="webprobe">WebProbe — built-in checks</option>
              <option value="all">All installed engines — WebProbe, then KageSec, then OpenOSINT</option>
              <option value="kagesec" disabled={!engines?.kagesec?.available}>KageSec — DAST + CVE templates{engines && !engines.kagesec?.available ? ' · not installed on this host' : ''}</option>
              <option value="openosint" disabled={!engines?.openosint?.available}>OpenOSINT — passive recon intel{engines && !engines.openosint?.available ? ' · not installed on this host' : ''}</option>
              <option value="argus" disabled={!engines?.argus?.available}>Argus — SAST / SCA / secrets over code{engines && !engines.argus?.available ? ' · not installed on this host' : ''}</option>
            </select><p className="field-hint">{engine === 'openosint' ? 'Passive intel only: DNS, WHOIS, RDAP, exposure and dorks. No vulnerability findings.' : engine === 'kagesec' ? 'Active DAST scan. Only use on targets you own or are authorized to test.' : engine === 'argus' ? 'Scans code, not a live URL: SAST, dependency CVEs, secrets. Give a repo above.' : engine === 'all' ? 'Runs each installed engine in sequence and merges the findings.' : 'The built-in WebProbe checks.'}</p></div>
          </section>
          <section className="form-section"><div className="form-section-title"><span>03</span><h2>Scan profile</h2></div>
            <div className="form-field"><label htmlFor="scan-profile">Profile</label><select id="scan-profile" className="text-input" value={profile} onChange={(event) => setProfile(event.target.value as ProfileId)}>{PROFILE_ORDER.filter((id) => !profiles || id in profiles).map((id) => <option key={id} value={id}>{profileLabel(id)}{profiles?.[id] ? ` · ${profiles[id].count} checks` : ''}</option>)}</select><p className="field-hint">{engine === 'webprobe' || engine === 'all' ? (PROFILE_DESCRIPTIONS[profile] || 'Run the checks included in this profile.') : 'Profile applies to WebProbe only; the other engines ignore it.'}</p></div>
          </section>
          <section className="form-section"><div className="form-section-title"><span>04</span><h2>Operational controls</h2></div>
            <div className="control-row"><div><label htmlFor="scan-rate">Rate limit</label><p>Maximum requests per second.</p></div><div className="range-control"><input id="scan-rate" type="range" min="0.5" max="20" step="0.5" value={rateLimit} onChange={(event) => setRateLimit(Number(event.target.value))} /><span className="mono">{rateLimit.toFixed(1)} RPS</span></div></div>
            <div className="control-row"><div><span className="control-label">Adaptive rate limiting</span><p>Back off when the target is under stress.</p></div><Toggle label="Adaptive rate limiting" checked={aimd} onChange={setAimd} /></div>
            <div className="control-row"><div><span className="control-label">Redact secrets</span><p>Remove sensitive values from evidence.</p></div><Toggle label="Redact secrets" checked={redact} onChange={setRedact} /></div>
          </section>
          <details className="advanced-details"><summary><span>Authentication &amp; webhook <span className="optional-label">OPTIONAL</span></span><ChevronDown size={15} /></summary>
            <p className="field-hint details-intro">Credentials are used for this assessment only and are not stored in this browser.</p>
            <div className="form-field"><label htmlFor="primary-cookie">Primary session cookie</label><input id="primary-cookie" className="text-input mono" type="password" autoComplete="off" placeholder="session=..." value={cookie} onChange={(event) => setCookie(event.target.value)} /></div>
            <div className="form-field"><label htmlFor="secondary-cookie">Secondary session cookie</label><input id="secondary-cookie" className="text-input mono" type="password" autoComplete="off" placeholder="session=..." value={secondaryCookie} onChange={(event) => setSecondaryCookie(event.target.value)} /><p className="field-hint">Used for cross-account authorization checks.</p></div>
            <div className="form-field"><label htmlFor="admin-cookie">Admin session cookie</label><input id="admin-cookie" className="text-input mono" type="password" autoComplete="off" placeholder="session=..." value={adminCookie} onChange={(event) => setAdminCookie(event.target.value)} /></div>
            <div className="form-field"><label htmlFor="webhook">Webhook URL</label><input id="webhook" className="text-input mono" type="url" placeholder="https://hooks.example.com/webprobe" value={webhook} onChange={(event) => setWebhook(event.target.value)} /></div>
          </details>
          {submitError && <p className="input-error submit-error" role="alert">{submitError}</p>}
          <div className="form-actions"><Link to="/" className="button button-secondary">Cancel</Link><Button type="submit" variant="primary" loading={loading}>Start assessment <ArrowRight size={14} /></Button></div>
        </div>
        <aside className="setup-aside" aria-label="Assessment authorization"><div className="setup-aside-icon"><ShieldCheck size={18} /></div><h2>Assess responsibly.</h2><p>Only scan targets you own or are explicitly authorized to test. Choose a rate that is appropriate for the target.</p><span>AUTHORIZATION REQUIRED</span></aside>
      </div>
    </form>
  </div>
}
