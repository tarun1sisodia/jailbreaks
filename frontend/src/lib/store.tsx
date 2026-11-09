import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import type { Engines, Health, Profiles, Scan, Settings } from '../types'
import { api, errorMessage } from './api'
import { EXAMPLE_SCANS } from './examples'
import { validApiBase } from './format'

export const DEFAULT_SETTINGS: Settings = {
  apiBase: 'https://jailbreaks-46uf.onrender.com/api', apiKey: '', defaultProfile: 'quick', rateLimit: 3, aimd: true, redact: true, theme: 'dark', reduceMotion: false,
}

function readSettings(): Settings {
  try {
    const stored = JSON.parse(localStorage.getItem('wp.settings') || '{}') as Partial<Settings>
    return {
      apiBase: typeof stored.apiBase === 'string' && validApiBase(stored.apiBase) ? stored.apiBase : DEFAULT_SETTINGS.apiBase,
      apiKey: typeof stored.apiKey === 'string' ? stored.apiKey : '',
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
  const currentApiBase = useRef(settings.apiBase)
  currentApiBase.current = settings.apiBase

  const updateSettings = useCallback((changes: Partial<Settings>) => {
    setSettings((current) => ({ ...current, ...changes }))
  }, [])

  useEffect(() => {
    api.setApiKey(settings.apiKey)
  }, [settings.apiKey])

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
    const base = settings.apiBase
    try { const result = await api.health(base); if (currentApiBase.current === base) setHealth(result) }
    catch { if (currentApiBase.current === base) setHealth(null) }
    finally { if (currentApiBase.current === base) setHealthLoading(false) }
  }, [settings.apiBase])
  const refreshScans = useCallback(async () => {
    const base = settings.apiBase
    try { const result = await api.scans(base); if (currentApiBase.current === base) { setScans(result); setScansError('') } }
    catch (error) { if (currentApiBase.current === base) setScansError(errorMessage(error)) }
  }, [settings.apiBase])
  const refreshProfiles = useCallback(async () => {
    const base = settings.apiBase
    try { const result = await api.profiles(base); if (currentApiBase.current === base) setProfiles(result) }
    catch { if (currentApiBase.current === base) setProfiles(null) }
  }, [settings.apiBase])
  const refreshEngines = useCallback(async () => {
    const base = settings.apiBase
    try { const result = await api.engines(base); if (currentApiBase.current === base) setEngines(result) }
    catch { if (currentApiBase.current === base) setEngines(null) }
  }, [settings.apiBase])

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
