import '../styles/pages/settings.css'
import { useState } from 'react'
import { api, errorMessage, saveBlob } from '../lib/api'
import { validApiBase } from '../lib/format'
import { useWorkspace } from '../lib/store'
import type { ProfileId, Theme } from '../types'
import { Button, ConfirmDialog, Toggle } from '../components/Primitives'

export function SettingsPage() {
  const { settings, updateSettings, health, healthLoading, refreshHealth, toast } = useWorkspace()
  const [base, setBase] = useState(settings.apiBase)
  const [baseError, setBaseError] = useState('')
  const [key, setKey] = useState(settings.apiKey)
  const [testing, setTesting] = useState(false)
  const [clearOpen, setClearOpen] = useState(false)
  const [testResult, setTestResult] = useState('')

  function saveBase() {
    const value = base.trim() === '/' ? '/' : base.trim().replace(/\/+$/, '') || '/api'
    if (!validApiBase(value)) { setBaseError('Use a same-origin path or an HTTPS API URL.'); return }
    setBaseError(''); setBase(value); updateSettings({ apiBase: value }); toast('Connection settings saved.', 'success')
  }
  async function testConnection() {
    const value = base.trim() === '/' ? '/' : base.trim().replace(/\/+$/, '') || '/api'
    if (!validApiBase(value)) { setBaseError('Use a same-origin path or an HTTPS API URL.'); return }
    setTesting(true); setBaseError(''); setTestResult('')
    try { const result = await api.health(value); setTestResult(`Connected · v${result.version}`); toast('Connection successful.', 'success') } catch (error) { setTestResult(errorMessage(error)); toast('Connection failed.', 'error') } finally { setTesting(false) }
  }
  function clearHistory() {
    try {
      const keys = Array.from({ length: localStorage.length }, (_, index) => localStorage.key(index)).filter((key): key is string => !!key && (key === 'wp.recentScanIds' || key.startsWith('wp.falsePositives.')))
      keys.forEach((key) => localStorage.removeItem(key))
      toast('Local scan data cleared.', 'success')
    } catch { toast('Could not clear local scan data.', 'error') }
    setClearOpen(false)
  }
  function saveKey() {
    updateSettings({ apiKey: key.trim() })
    toast('API key saved in this browser.', 'success')
  }
  function exportSettings() {
    const { apiKey: _apiKey, ...exportable } = settings
    saveBlob(new Blob([JSON.stringify(exportable, null, 2)], { type: 'application/json' }), 'webprobe-settings.json')
    toast('Settings exported (API key excluded).', 'success')
  }
  return <div className="page standard-page settings-page">
    <div className="page-heading"><div><div className="eyebrow page-eyebrow">WORKSPACE / PREFERENCES</div><h1>Settings</h1><p>Configure your connection and assessment defaults.</p></div></div>
    <div className="page-rule" />
    <section className="settings-section"><div className="settings-section-heading"><h2>Backend connection</h2><p>Where this workspace sends assessment requests.</p></div>
      <div className="setting-row setting-row-top"><div><label htmlFor="api-base">API base URL</label><p>Use a same-origin path or an HTTPS URL.</p></div><div className="setting-control api-control"><input id="api-base" className={`text-input mono ${baseError ? 'input-invalid' : ''}`} value={base} onChange={(event) => { setBase(event.target.value); setBaseError(''); setTestResult('') }} /><div className="setting-inline-actions"><span className="settings-connection"><span className={`dot ${health ? 'dot-success' : healthLoading ? 'dot-info' : 'dot-critical'}`} />{health ? `Connected · v${health.version}` : healthLoading ? 'Connecting' : 'Backend offline'}</span><Button size="small" onClick={() => void testConnection()} loading={testing}>Test</Button><Button size="small" onClick={saveBase}>Save</Button></div>{baseError && <p className="input-error" role="alert">{baseError}</p>}{testResult && <p className="field-hint" aria-live="polite">{testResult}</p>}</div></div>
      <div className="setting-row setting-row-top"><div><label htmlFor="api-key">API key</label><p>Sent as X-API-Key on scan, report and list requests. Stored only in this browser.</p></div><div className="setting-control api-control"><input id="api-key" className="text-input mono" type="password" autoComplete="off" placeholder="WEBPROBE_API_KEY" value={key} onChange={(event) => setKey(event.target.value)} /><div className="setting-inline-actions"><Button size="small" onClick={saveKey}>Save key</Button></div><p className="field-hint">Without it, scans return 401. /health and /engines stay public.</p></div></div>
      {!health && !healthLoading && <div className="setting-row"><div /><button className="subtle-link setting-control-left" onClick={() => void refreshHealth()}>Retry connection</button></div>}
    </section>
    <section className="settings-section"><div className="settings-section-heading"><h2>Scan defaults</h2><p>Applied when you start a new assessment.</p></div>
      <div className="setting-row"><div><label htmlFor="default-profile">Default profile</label></div><div className="setting-control"><select id="default-profile" className="text-input" value={settings.defaultProfile} onChange={(event) => updateSettings({ defaultProfile: event.target.value as ProfileId })}><option value="quick">Quick</option><option value="owasp">OWASP</option><option value="full">Full</option><option value="api">API</option></select></div></div>
      <div className="setting-row"><div><label htmlFor="default-rate">Rate limit</label><p>Requests per second.</p></div><div className="setting-control range-control"><input id="default-rate" type="range" min="0.5" max="20" step="0.5" value={settings.rateLimit} onChange={(event) => updateSettings({ rateLimit: Number(event.target.value) })} /><span className="mono">{settings.rateLimit.toFixed(1)} RPS</span></div></div>
      <div className="setting-row"><div><span className="control-label">Adaptive rate limiting</span><p>Automatically back off when needed.</p></div><div className="setting-control"><Toggle label="Adaptive rate limiting by default" checked={settings.aimd} onChange={(aimd) => updateSettings({ aimd })} /></div></div>
      <div className="setting-row"><div><span className="control-label">Redact secrets</span><p>Scrub sensitive values from evidence.</p></div><div className="setting-control"><Toggle label="Redact secrets by default" checked={settings.redact} onChange={(redact) => updateSettings({ redact })} /></div></div>
    </section>
    <section className="settings-section"><div className="settings-section-heading"><h2>Appearance</h2><p>Adjust the workspace to your preference.</p></div>
      <div className="setting-row"><div><span className="control-label">Theme</span></div><div className="setting-control theme-options">{(['system', 'dark', 'light'] as Theme[]).map((theme) => <button key={theme} className={settings.theme === theme ? 'active' : ''} aria-pressed={settings.theme === theme} onClick={() => updateSettings({ theme })}>{theme.charAt(0).toUpperCase() + theme.slice(1)}</button>)}</div></div>
      <div className="setting-row"><div><span className="control-label">Reduce motion</span></div><div className="setting-control"><Toggle label="Reduce motion" checked={settings.reduceMotion} onChange={(reduceMotion) => updateSettings({ reduceMotion })} /></div></div>
    </section>
    <section className="settings-section"><div className="settings-section-heading"><h2>Data</h2><p>Local preferences are stored in this browser.</p></div>
      <div className="setting-row data-row"><div><button className="danger-link" onClick={() => setClearOpen(true)}>Clear local history</button><p>Does not delete reports on the server.</p></div><div className="setting-control"><Button onClick={exportSettings}>Export settings</Button></div></div>
    </section>
    {clearOpen && <ConfirmDialog title="Clear local history?" description="This clears saved scan IDs and false-positive annotations from this browser. Reports on the server will not be deleted." confirmLabel="Clear local data" onClose={() => setClearOpen(false)} onConfirm={clearHistory} />}
  </div>
}
