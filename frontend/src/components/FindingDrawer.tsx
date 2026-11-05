import '../styles/components/finding-drawer.css'
import { useState } from 'react'
import { ExternalLink, X } from 'lucide-react'
import type { Finding, PocMessage } from '../types'
import { safeExternalUrl } from '../lib/format'
import { useWorkspace } from '../lib/store'
import { Button, Dialog, SeverityLabel } from './Primitives'

function messageText(message: PocMessage | null | undefined, request: boolean): string {
  if (!message) return ''
  const head = request ? [message.method, message.url].filter(Boolean).join(' ') : message.status ? `HTTP response · ${message.status}` : ''
  const headers = Object.entries(message.headers || {}).map(([key, value]) => `${key}: ${value}`).join('\n')
  return [head, headers, message.body_text].filter(Boolean).join('\n')
}

export function FindingDrawer({ finding, isFalsePositive, toggleFalsePositive, close }: { finding: Finding; isFalsePositive: boolean; toggleFalsePositive: () => void; close: () => void }) {
  const [tab, setTab] = useState<'overview' | 'evidence' | 'remediation'>('overview')
  const { toast } = useWorkspace()
  const request = messageText(finding.poc?.request, true)
  const response = messageText(finding.poc?.response, false)
  async function copy(text: string, message: string) {
    try { await navigator.clipboard.writeText(text); toast(message, 'success') } catch { toast('Could not copy to clipboard.', 'error') }
  }
  const cweMatch = finding.cwe.match(/^CWE-(\d+)$/i)
  const targetLink = safeExternalUrl(finding.url)
  return <Dialog labelledBy="finding-title" onClose={close} className="finding-drawer">
    <div className="drawer-header">
      <div className="drawer-heading"><SeverityLabel severity={finding.severity} /><h2 id="finding-title">{finding.title}</h2><button className="icon-button drawer-close" aria-label="Close finding details" onClick={close}><X size={16} /></button></div>
      <div className="drawer-cvss mono"><span>{finding.score === null ? '—' : finding.score.toFixed(1)}</span>{finding.vector && <><span className="drawer-dot-separator">·</span><span className="cvss-vector" title={finding.vector}>{finding.vector}</span><button onClick={() => void copy(finding.vector, 'CVSS vector copied.')} className="inline-copy">Copy</button></>}</div>
    </div>
    <div className="drawer-tabs" role="tablist" aria-label="Finding details">{(['overview', 'evidence', 'remediation'] as const).map((item) => <button key={item} role="tab" aria-selected={tab === item} className={tab === item ? 'active' : ''} onClick={() => setTab(item)}>{item.charAt(0).toUpperCase() + item.slice(1)}</button>)}</div>
    <div className="drawer-body" role="tabpanel">
      {tab === 'overview' && <>
        <div className="drawer-section"><div className="eyebrow">OVERVIEW</div><p className="drawer-prose">{finding.description || 'No description was provided by the scanner.'}</p></div>
        <div className="drawer-section drawer-metadata">
          <div><span>Endpoint</span><strong className="mono">{finding.method && `${finding.method} `}{finding.endpoint}</strong></div>
          {finding.parameter && <div><span>Parameter</span><strong className="mono">{finding.parameter}</strong></div>}
          {finding.phase && <div><span>Phase</span><strong>{finding.phase}</strong></div>}
          {finding.category && <div><span>Category</span><strong>{finding.category.replaceAll('_', ' ')}</strong></div>}
          {finding.cwe && <div><span>Classification</span><strong>{cweMatch ? <a href={`https://cwe.mitre.org/data/definitions/${cweMatch[1]}.html`} target="_blank" rel="noreferrer">{finding.cwe} <ExternalLink size={11} /></a> : finding.cwe}{finding.owasp && <> <span className="metadata-separator">·</span> <a href="https://owasp.org/Top10/" target="_blank" rel="noreferrer">{finding.owasp} <ExternalLink size={11} /></a></>}</strong></div>}
          {!finding.cwe && finding.owasp && <div><span>Classification</span><strong><a href="https://owasp.org/Top10/" target="_blank" rel="noreferrer">{finding.owasp} <ExternalLink size={11} /></a></strong></div>}
          {targetLink && <div><span>Target</span><strong><a className="mono" href={targetLink} target="_blank" rel="noreferrer">Open endpoint <ExternalLink size={11} /></a></strong></div>}
        </div>
        {finding.evidence && <div className="drawer-section"><div className="eyebrow">EVIDENCE</div><pre className="code-block"><code>{finding.evidence}</code></pre><button className="subtle-link" onClick={() => setTab('evidence')}>View evidence <span>→</span></button></div>}
        {isFalsePositive && <p className="local-annotation">Marked as a false positive in this browser.</p>}
      </>}
      {tab === 'evidence' && <>
        <div className="drawer-section"><div className="eyebrow">SCANNER EVIDENCE</div>{finding.evidence ? <pre className="code-block"><code>{finding.evidence}</code></pre> : <p className="drawer-muted">No evidence was provided for this finding.</p>}</div>
        {request && <div className="drawer-section"><div className="eyebrow">REQUEST</div><pre className="code-block"><code>{request}</code></pre></div>}
        {response && <div className="drawer-section"><div className="eyebrow">RESPONSE</div><pre className="code-block"><code>{response}</code></pre></div>}
        {finding.poc?.curl && <button className="subtle-link" onClick={() => void copy(finding.poc!.curl!, 'cURL command copied.')}>Copy cURL</button>}
      </>}
      {tab === 'remediation' && <div className="drawer-section"><div className="eyebrow">REMEDIATION</div><p className="drawer-prose pre-line">{finding.remediation || 'No remediation was provided by the scanner.'}</p>{finding.remediation && <button className="subtle-link" onClick={() => void copy(finding.remediation, 'Remediation copied.')}>Copy remediation</button>}</div>}
    </div>
    <div className="drawer-footer"><button className="false-positive" onClick={toggleFalsePositive}>{isFalsePositive ? 'Undo false positive' : 'Mark as false positive'}</button><Button onClick={close}>Close</Button></div>
  </Dialog>
}
