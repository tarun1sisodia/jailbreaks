import { describe, expect, it } from 'vitest'
import type { Report, Scan } from '../types'
import { enginesThatDidNotComplete, reportNotice, requestedEngineOf } from './reportNotices'

function scan(overrides: Partial<Scan> = {}): Scan {
  return {
    scan_id: 'scan-1',
    url: 'https://example.com',
    profile: 'quick',
    engine: 'webprobe',
    status: 'completed',
    created_at: 1,
    ...overrides,
  }
}

function report(metadata: Report['metadata']): Report {
  return { metadata, findings: [] }
}

describe('report notices', () => {
  it('stays hidden for a normal completed scan', () => {
    expect(reportNotice(scan(), report({ engine: 'webprobe', engines: ['webprobe'] }))).toBeNull()
  })

  it('describes a fallback using the requested engine, not a hardcoded list', () => {
    const notice = reportNotice(
      scan({ fallback: true, requested_engine: 'all', note: 'Full engines were asleep, ran WebProbe only.' }),
      report({ engine: 'webprobe', requested_engine: 'all', fallback: true, note: 'Full engines were asleep, ran WebProbe only.' }),
    )
    expect(notice?.kind).toBe('fallback')
    expect(notice?.detail).toContain('Requested engine: all.')
    expect(notice?.detail).toContain('KageSec')
    expect(notice?.detail).toContain('OpenOSINT')
  })

  it('does not mention unrelated engines for a single-engine fallback', () => {
    const notice = reportNotice(
      scan({ fallback: true, requested_engine: 'kagesec' }),
      report({ engine: 'webprobe', requested_engine: 'kagesec', fallback: true }),
    )
    expect(notice?.detail).toContain('kagesec did not run.')
    expect(notice?.detail).not.toContain('OpenOSINT')
  })

  it('lists only engines that failed or were unavailable', () => {
    const data = report({
      engine: 'all',
      partial: true,
      engines: ['webprobe'],
      engines_breakdown: {
        webprobe: { ran: true, succeeded: true, findings_count: 2 },
        kagesec: { ran: true, succeeded: false, findings_count: 0, error: 'timeout' },
        openosint: { ran: false, succeeded: false, findings_count: 0, error: 'not installed' },
      },
    })
    expect(enginesThatDidNotComplete(data)).toEqual(['kagesec', 'openosint'])
    const notice = reportNotice(scan({ partial: true }), data)
    expect(notice?.kind).toBe('partial')
    expect(notice?.detail).toContain('kagesec, openosint')
  })

  it('falls back to the successful-engine list for older reports', () => {
    const data = report({ engine: 'all', partial: true, engines: ['webprobe', 'kagesec'] })
    expect(enginesThatDidNotComplete(data)).toEqual(['openosint'])
  })

  it('resolves the requested engine from the scan when report metadata is old', () => {
    expect(requestedEngineOf(scan({ requested_engine: 'openosint' }), report({ engine: 'webprobe' }))).toBe('openosint')
  })

  it('surfaces a failed assessment even when no engine produced findings', () => {
    const data = report({
      engine: 'all',
      engines: [],
      engines_breakdown: {
        webprobe: { ran: true, succeeded: false, findings_count: 0, error: 'CLI exited 1' },
        kagesec: { ran: false, succeeded: false, findings_count: 0, error: 'not installed' },
        openosint: { ran: false, succeeded: false, findings_count: 0, error: 'not installed' },
      },
    })
    const notice = reportNotice(scan({ status: 'failed', error: 'The scanner failed.' }), data)
    expect(notice?.kind).toBe('failed')
    expect(notice?.detail).toContain('webprobe, kagesec, openosint')
  })
})
