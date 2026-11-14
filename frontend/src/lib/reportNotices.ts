import type { Report, Scan } from '../types'

export interface ReportNotice {
  kind: 'fallback' | 'partial' | 'failed'
  title: string
  detail: string
  engines: string[]
}

export function requestedEngineOf(scan: Scan | null, report: Report | null): string {
  return report?.metadata?.requested_engine || scan?.requested_engine || report?.metadata?.engine || scan?.engine || ''
}

export function enginesThatDidNotComplete(report: Report | null): string[] {
  const breakdown = report?.metadata?.engines_breakdown || report?.metadata?.engine_breakdown
  if (breakdown) {
    return Object.entries(breakdown)
      .filter(([, info]) => !info || info.ran === false || info.succeeded === false)
      .map(([name]) => name)
  }
  // Older reports predate engines_breakdown. For engine=all, anything missing
  // from the successful-engine list did not complete.
  if (report?.metadata?.engine === 'all') {
    const ran = new Set(report.metadata.engines || [])
    return ['webprobe', 'kagesec', 'openosint'].filter((name) => !ran.has(name))
  }
  return []
}

export function reportNotice(scan: Scan | null, report: Report | null): ReportNotice | null {
  const meta = report?.metadata
  const fallback = Boolean(meta?.fallback || scan?.fallback)
  const partial = Boolean(meta?.partial || scan?.partial)
  const failed = scan?.status === 'failed' || scan?.status === 'error'
  if (!fallback && !partial && !failed) return null

  const requested = requestedEngineOf(scan, report)
  if (fallback) {
    const requestedText = requested && requested !== 'webprobe' ? ` Requested engine: ${requested}.` : ''
    const missingText = requested === 'all'
      ? ' KageSec, OpenOSINT, and Argus (when a repo was supplied) did not run.'
      : requested && requested !== 'webprobe'
        ? ` ${requested} did not run.`
        : '';
    return {
      kind: 'fallback',
      title: 'Fallback scan:',
      detail: `${meta?.note || scan?.note || 'The engine box was unavailable; WebProbe ran instead.'}${requestedText}${missingText}`,
      engines: enginesThatDidNotComplete(report),
    }
  }

  const missing = enginesThatDidNotComplete(report)
  if (partial) {
    return {
      kind: 'partial',
      title: 'Partial assessment:',
      detail: `${meta?.note || scan?.note || 'Some engines did not complete successfully.'}${missing.length ? ` Engines that did not complete: ${missing.join(', ')}.` : ''}`,
      engines: missing,
    }
  }
  return {
    kind: 'failed',
    title: 'Assessment failed:',
    detail: `${meta?.note || scan?.note || scan?.error || 'The assessment did not complete.'}${missing.length ? ` Engines that did not complete: ${missing.join(', ')}.` : ''}`,
    engines: missing,
  }
}
