import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import type { Engines, Health, Profiles, Scan, Settings } from '../types'
import { api, errorMessage } from './api'
import { EXAMPLE_SCANS } from './examples'

export const DEFAULT_SETTINGS: Settings = {
  defaultProfile: 'quick', rateLimit: 3, aimd: true, redact: true, theme: 'dark', reduceMotion: false,
}

function readSettings(): Settings {
  try {
    const stored = JSON.parse(localStorage.getItem('wp.settings') || '{}') as Partial<Settings>
    // Legacy connection fields (if present from an older build) are dropped
    // here and never sent anywhere. The proxy holds the backend keys.
    return {
      defaultProfile: stored.defaultProfile && ['quick', 'owasp', 'full', 'api'].includes(stored.defaultProfile) ? stored.defaultProfile : DEFAULT_SETTINGS.defaultProfile,
      rateLimit: typeof stored.rateLimit === 'number' && Number.isFinite(stored.rateLimit) ? Math.max(0.5, Math.min(20, stored.rateLimit)) : DEFAULT_SETTINGS.rateLimit,
      aimd: typeof stored.aimd === 'boolean' ? stored.aimd : DEFAULT_SETTINGS.aimd,
      redact: typeof stored.redact === 'boolean' ? stored.redact : DEFAULT_SETTINGS.redact,
      theme: stored.theme && ['system', 'dark', 'light'].includes(stored.theme) ? stored.theme : DEFAULT_SETTINGS.theme,
      reduceMotion: typeof stored.reduceMotion === 'boolean' ? stored.reduceMotion : DEFAULT_SETTINGS.reduceMotion,
    }
  } catch {
    return DEFAULT_SETTINGS
  }
}

interface WorkspaceContext {
  settings: Settings
  updateSettings: (changes: Partial<Settings>) => void
  health: Health | null
  healthLoading: boolean
  scans: Scan[] | null
  visibleScans: Scan[]
  showingExamples: boolean
  scansError: string
  profiles: Profiles | null
  engines: Engines | null
  refreshHealth: () => Promise<void>
  refreshScans: () => Promise<void>
  refreshProfiles: () => Promise<void>
  refreshEngines: () => Promise<void>
  toast: (message: string, kind?: 'success' | 'error' | 'info') => void
}

interface ToastItem { id: number; message: string; kind: 'success' | 'error' | 'info' }
const Context = createContext<WorkspaceContext | null>(null)

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<Settings>(readSettings)
  const [health, setHealth] = useState<Health | null>(null)
  const [healthLoading, setHealthLoading] = useState(true)
  const [scans, setScans] = useState<Scan[] | null>(null)
  const [scansError, setScansError] = useState('')
  const [profiles, setProfiles] = useState<Profiles | null>(null)
  const [engines, setEngines] = useState<Engines | null>(null)
  const [toasts, setToasts] = useState<ToastItem[]>([])

  const updateSettings = useCallback((changes: Partial<Settings>) => {
    setSettings((current) => ({ ...current, ...changes }))
  }, [])

  useEffect(() => {
    try { localStorage.setItem('wp.settings', JSON.stringify(settings)) } catch { /* Storage may be unavailable. */ }
    const media = window.matchMedia('(prefers-color-scheme: light)')
    const applyTheme = () => {
      document.documentElement.dataset.theme = settings.theme === 'system' ? (media.matches ? 'light' : 'dark') : settings.theme
    }
    applyTheme()
    media.addEventListener('change', applyTheme)
    document.documentElement.dataset.reduceMotion = String(settings.reduceMotion)
    return () => media.removeEventListener('change', applyTheme)
  }, [settings])

  const refreshHealth = useCallback(async () => {
    try { setHealth(await api.health()) }
    catch { setHealth(null) }
    finally { setHealthLoading(false) }
  }, [])
  const refreshScans = useCallback(async () => {
    try { setScans(await api.scans()); setScansError('') }
    catch (error) { setScansError(errorMessage(error)) }
  }, [])
  const refreshProfiles = useCallback(async () => {
    try { setProfiles(await api.profiles()) }
    catch { setProfiles(null) }
  }, [])
  const refreshEngines = useCallback(async () => {
    try { setEngines(await api.engines()) }
    catch { setEngines(null) }
  }, [])

  useEffect(() => {
    setHealth(null)
    setHealthLoading(true)
    setScans(null)
    setProfiles(null)
    setEngines(null)
    void refreshHealth()
    void refreshScans()
    void refreshEngines()
    const healthInterval = window.setInterval(() => { void refreshHealth() }, 30000)
    const scansInterval = window.setInterval(() => { void refreshScans() }, 10000)
    const onFocus = () => { void refreshHealth(); void refreshScans() }
    window.addEventListener('focus', onFocus)
    return () => { window.clearInterval(healthInterval); window.clearInterval(scansInterval); window.removeEventListener('focus', onFocus) }
  }, [refreshHealth, refreshScans, refreshProfiles])

  useEffect(() => {
    if (health && !profiles) void refreshProfiles()
    if (health && !engines) void refreshEngines()
  }, [health, profiles, engines, refreshProfiles, refreshEngines])

  const toast = useCallback((message: string, kind: ToastItem['kind'] = 'info') => {
    const id = Date.now() + Math.random()
    setToasts((items) => [...items.slice(-3), { id, message, kind }])
    window.setTimeout(() => setToasts((items) => items.filter((item) => item.id !== id)), kind === 'error' ? 8000 : 4500)
  }, [])

  const showingExamples = !scans || scans.length === 0
  const value = useMemo(() => ({
    settings, updateSettings, health, healthLoading, scans, visibleScans: showingExamples ? EXAMPLE_SCANS : (scans || []),
    showingExamples, scansError, profiles, engines, refreshHealth, refreshScans, refreshProfiles, refreshEngines, toast,
  }), [settings, updateSettings, health, healthLoading, scans, showingExamples, scansError, profiles, engines, refreshHealth, refreshScans, refreshProfiles, refreshEngines, toast])

  return <Context.Provider value={value}>
    {children}
    <div className="toast-stack" aria-live="polite" aria-atomic="false">
      {toasts.map((item) => <div className={`toast toast-${item.kind}`} key={item.id}>
        <span className={`dot ${item.kind === 'success' ? 'dot-success' : item.kind === 'error' ? 'dot-critical' : 'dot-info'}`} />
        <span>{item.message}</span>
        <button className="toast-close" aria-label="Dismiss notification" onClick={() => setToasts((items) => items.filter((entry) => entry.id !== item.id))}>×</button>
      </div>)}
    </div>
  </Context.Provider>
}

export function useWorkspace(): WorkspaceContext {
  const context = useContext(Context)
  if (!context) throw new Error('useWorkspace must be inside WorkspaceProvider')
  return context
}

export function rememberScan(id: string): void {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem('wp.recentScanIds') || '[]')
    const ids = Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === 'string') : []
    localStorage.setItem('wp.recentScanIds', JSON.stringify([id, ...ids.filter((entry) => entry !== id)].slice(0, 20)))
  } catch { /* The server remains the source of truth. */ }
}
