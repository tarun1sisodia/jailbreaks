import { describe, expect, it } from 'vitest'
import { EXAMPLE_SCANS, exampleReport } from './examples'
import { duration, normalizeFinding, severityCounts, validApiBase, validHttpUrl } from './format'

describe('actual scanner data', () => {
  it('normalizes the engine finding shape without inventing missing fields', () => {
    const finding = normalizeFinding({
      title: 'Missing header', severity: 'high', category: 'headers', url: 'https://example.com/path?q=1',
      phase: 6, evidence: 'No header', remediation: 'Set the header',
      extra: { cvss: { score: 7.1, vector: 'CVSS:3.1/test' }, taxonomy: { cwe: 'CWE-693', owasp: 'A05:2021' } },
    }, 0)
    expect(finding).toMatchObject({ endpoint: '/path?q=1', phase: 'Infra', score: 7.1, cwe: 'CWE-693', evidence: 'No header', method: '' })
    expect(normalizeFinding({ title: 'Incomplete' }, 1).score).toBeNull()
    expect(severityCounts([finding]).high).toBe(1)
  })
  it('formats durations and validates scan and connection URLs', () => {
    expect(duration(724)).toBe('12:04')
    expect(duration(3661)).toBe('1:01:01')
    expect(duration()).toBe('—')
    expect(validHttpUrl('https://example.com')).toBe(true)
    expect(validHttpUrl('ftp://example.com')).toBe(false)
    expect(validHttpUrl('https://name:password@example.com')).toBe(false)
    expect(validApiBase('/api')).toBe(true)
    expect(validApiBase('/')).toBe(true)
    expect(validApiBase('https://scanner.example.com')).toBe(true)
    expect(validApiBase('//other.example.com')).toBe(false)
    expect(validApiBase('http://localhost:8080')).toBe(false)
  })
  it('keeps labeled example scan counts consistent with example reports', () => {
    for (const scan of EXAMPLE_SCANS.filter((item) => item.status === 'completed')) {
      const report = exampleReport(scan.scan_id)!
      expect(report.findings).toHaveLength(scan.findings_count!)
      expect(severityCounts(report.findings.map(normalizeFinding))).toEqual(scan.severity_summary)
      expect(scan.example).toBe(true)
    }
  })
})
