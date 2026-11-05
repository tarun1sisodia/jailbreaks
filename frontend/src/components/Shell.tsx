import { Component, Suspense, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import {
  ArrowRight, BookOpen, Command, LayoutDashboard, Menu, Moon, Plus, ScanLine,
  Search, Settings2, ShieldCheck, Sun, X,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { useWorkspace } from '../lib/store'
import { Dialog, EmptyState } from './Primitives'

const navigation: { to: string; label: string; icon: LucideIcon }[] = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/scans', label: 'Scans', icon: ScanLine },
  { to: '/catalog', label: 'Catalog', icon: BookOpen },
  { to: '/settings', label: 'Settings', icon: Settings2 },
]

function Sidebar({ close }: { close?: () => void }) {
  const { health, healthLoading } = useWorkspace()
  return <aside className="sidebar" aria-label="Workspace navigation">
    <Link to="/" className="brand" onClick={close} aria-label="WebProbe dashboard">
      <span className="brand-mark"><ShieldCheck size={19} strokeWidth={1.75} /></span>
      <span>WebProbe</span>
    </Link>
    <div className="sidebar-heading">WORKSPACE</div>
    <nav className="sidebar-nav" aria-label="Main navigation">
      {navigation.map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} end={to === '/'} onClick={close} className={({ isActive }) => `nav-item ${isActive ? 'nav-active' : ''}`}>
        <Icon size={16} strokeWidth={1.75} /><span>{label}</span>
      </NavLink>)}
    </nav>
    <div className="sidebar-spacer" />
    <div className="sidebar-bottom">
      <Link to="/scans/new" onClick={close} className="sidebar-new"><Plus size={15} /><span>New scan</span><ArrowRight className="sidebar-new-arrow" size={13} /></Link>
      <div className="sidebar-divider" />
      <Link to="/settings" onClick={close} className="connection">
        <span className="connection-line"><span className={`dot ${health ? 'dot-success' : healthLoading ? 'dot-info' : 'dot-critical'}`} />{health ? 'Connected' : healthLoading ? 'Connecting' : 'Backend offline'}</span>
        <span className="connection-version">{health?.version ? `Engine v${health.version}` : 'Connection settings'}</span>
      </Link>
      <div className="sidebar-caption">AUTHORIZED TESTING ONLY</div>
    </div>
  </aside>
}

function Breadcrumbs() {
  const { pathname } = useLocation()
  const pieces = pathname.split('/').filter(Boolean)
  let crumbs: { label: string; to?: string }[] = [{ label: 'Dashboard' }]
  if (pieces[0] === 'scans') {
    crumbs = [{ label: 'Scans', to: '/scans' }]
    if (pieces[1] === 'new') crumbs.push({ label: 'New scan' })
    else if (pieces[1]) {
      crumbs.push({ label: pieces[1].startsWith('example-') ? 'Example scan' : pieces[1].slice(0, 8), to: pieces[2] ? `/scans/${pieces[1]}` : undefined })
      if (pieces[2] === 'report') crumbs.push({ label: 'Report' })
    }
  } else if (pieces[0] === 'catalog') crumbs = [{ label: 'Catalog' }]
  else if (pieces[0] === 'settings') crumbs = [{ label: 'Settings' }]
  return <div className="breadcrumbs" aria-label="Breadcrumb">
    <span className="breadcrumb-workspace">Workspace</span><span className="breadcrumb-separator">/</span>
    {crumbs.map((crumb, index) => <span className="breadcrumb-piece" key={`${crumb.label}-${index}`}>
      {index > 0 && <span className="breadcrumb-separator">/</span>}
      {crumb.to && index !== crumbs.length - 1 ? <Link to={crumb.to}>{crumb.label}</Link> : <span className={index === crumbs.length - 1 ? 'breadcrumb-current' : ''}>{crumb.label}</span>}
    </span>)}
  </div>
}

interface CommandAction { label: string; detail: string; action: () => void }
function CommandPalette({ close }: { close: () => void }) {
  const navigate = useNavigate()
  const { settings, updateSettings } = useWorkspace()
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(0)
  const actions: CommandAction[] = useMemo(() => [
    { label: 'Dashboard', detail: 'Navigate', action: () => navigate('/') },
    { label: 'Scans', detail: 'Navigate', action: () => navigate('/scans') },
    { label: 'New scan', detail: 'Action', action: () => navigate('/scans/new') },
    { label: 'Check catalog', detail: 'Navigate', action: () => navigate('/catalog') },
    { label: 'Settings', detail: 'Navigate', action: () => navigate('/settings') },
    { label: 'Toggle theme', detail: 'Action', action: () => updateSettings({ theme: settings.theme === 'light' ? 'dark' : 'light' }) },
  ], [navigate, settings.theme, updateSettings])
  const filtered = actions.filter((item) => `${item.label} ${item.detail}`.toLowerCase().includes(query.toLowerCase().trim()))
  const run = (item: CommandAction) => { item.action(); close() }
  return <Dialog labelledBy="command-title" onClose={close} className="command-dialog">
    <div className="command-input-wrap"><Search size={17} /><label className="sr-only" id="command-title" htmlFor="command-search">Search WebProbe</label><input id="command-search" data-autofocus placeholder="Search pages and actions..." value={query} onChange={(event) => { setQuery(event.target.value); setSelected(0) }} onKeyDown={(event) => {
      if (event.key === 'ArrowDown') { event.preventDefault(); setSelected((current) => Math.min(current + 1, filtered.length - 1)) }
      if (event.key === 'ArrowUp') { event.preventDefault(); setSelected((current) => Math.max(current - 1, 0)) }
      if (event.key === 'Enter' && filtered[selected]) run(filtered[selected])
    }} /><kbd>esc</kbd></div>
    <div className="command-results">
      <div className="command-section-label">QUICK ACCESS</div>
      {filtered.length ? filtered.map((item, index) => <button key={item.label} className={`command-result ${index === selected ? 'selected' : ''}`} onMouseEnter={() => setSelected(index)} onClick={() => run(item)}><span>{item.label}</span><span>{item.detail}</span></button>) : <p className="command-empty">No results for “{query}”.</p>}
    </div>
    <div className="command-footer"><span>↑↓ Navigate</span><span>↵ Select</span><span>Esc Close</span></div>
  </Dialog>
}

function PageLoading() {
  return <div className="page standard-page" role="status" aria-live="polite"><div className="loading-copy"><span className="spinner-inline" aria-hidden="true" />Loading page...</div></div>
}

// A stale or unavailable chunk should not take down the persistent workspace shell.
class PageErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }
  static getDerivedStateFromError() { return { failed: true } }
  render() {
    if (this.state.failed) return <div className="page standard-page" role="alert"><EmptyState title="Couldn't load this page." description="The page may have changed or your connection was interrupted." action={<><button className="button button-primary" onClick={() => window.location.reload()}>Reload page</button><Link className="button button-ghost" to="/">Back to dashboard</Link></>} /></div>
    return this.props.children
  }
}

export function Shell() {
  const { pathname } = useLocation()
  const { settings, updateSettings } = useWorkspace()
  const [commandOpen, setCommandOpen] = useState(false)
  const [mobileNav, setMobileNav] = useState(false)
  const [systemLight, setSystemLight] = useState(() => window.matchMedia('(prefers-color-scheme: light)').matches)
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: light)')
    const update = () => setSystemLight(media.matches)
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [])
  useEffect(() => {
    const shortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); setCommandOpen((open) => !open) }
    }
    window.addEventListener('keydown', shortcut)
    return () => window.removeEventListener('keydown', shortcut)
  }, [])
  const isLight = settings.theme === 'light' || (settings.theme === 'system' && systemLight)
  return <div className="app-shell">
    <div className="desktop-sidebar"><Sidebar /></div>
    {mobileNav && <Dialog labelledBy="mobile-navigation-title" onClose={() => setMobileNav(false)} className="mobile-nav-content"><span id="mobile-navigation-title" className="sr-only">Workspace navigation</span><button className="icon-button mobile-nav-close" aria-label="Close navigation" onClick={() => setMobileNav(false)}><X size={17} /></button><Sidebar close={() => setMobileNav(false)} /></Dialog>}
    <div className="app-main">
      <header className="topbar">
        <div className="topbar-left"><button className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setMobileNav(true)}><Menu size={18} /></button><Breadcrumbs /></div>
        <div className="topbar-actions">
          <button className="search-trigger" onClick={() => setCommandOpen(true)} aria-label="Search K, open command palette"><Search size={14} /><span>Search</span><kbd aria-hidden="true"><Command size={11} /> K</kbd></button>
          <button className="icon-button theme-button" onClick={() => updateSettings({ theme: isLight ? 'dark' : 'light' })} aria-label={isLight ? 'Switch to dark theme' : 'Switch to light theme'}>{isLight ? <Moon size={16} /> : <Sun size={16} />}</button>
          <span className="avatar" aria-label="WebProbe workspace">WP</span>
        </div>
      </header>
      <main><PageErrorBoundary key={pathname}><Suspense fallback={<PageLoading />}><Outlet /></Suspense></PageErrorBoundary></main>
    </div>
    {commandOpen && <CommandPalette close={() => setCommandOpen(false)} />}
  </div>
}
