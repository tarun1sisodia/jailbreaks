import { useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { LoaderCircle, X } from 'lucide-react'
import type { ButtonHTMLAttributes, ReactNode } from 'react'
import type { ScanStatus, Severity } from '../types'
import { capitalize } from '../lib/format'

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
  size?: 'normal' | 'small'
  loading?: boolean
  icon?: ReactNode
}
export function Button({ variant = 'secondary', size = 'normal', loading, icon, children, className = '', disabled, ...props }: ButtonProps) {
  return <button className={`button button-${variant} button-${size} ${className}`} disabled={disabled || loading} {...props}>
    {loading ? <LoaderCircle className="spinner" size={14} /> : icon}
    {children}
  </button>
}

export function SeverityLabel({ severity, compact = false }: { severity: Severity; compact?: boolean }) {
  return <span className={`severity-label severity-${severity}`}><span className={`dot dot-${severity}`} />{compact ? severity.charAt(0).toUpperCase() : capitalize(severity)}</span>
}

export function StatusLabel({ status }: { status: ScanStatus }) {
  const normalized = status === 'error' ? 'failed' : status
  const label = normalized === 'completed' ? 'Completed' : capitalize(normalized)
  return <span className={`status-label status-${normalized}`}><span className={`dot status-dot status-dot-${normalized}`} />{label}</span>
}

export function EmptyState({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return <div className="empty-state"><p className="empty-title">{title}</p>{description && <p>{description}</p>}{action && <div className="empty-action">{action}</div>}</div>
}

export function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (value: boolean) => void; label: string }) {
  return <button type="button" role="switch" aria-checked={checked} aria-label={label} onClick={() => onChange(!checked)} className={`toggle ${checked ? 'toggle-on' : ''}`}><span /></button>
}

export function Dialog({ children, onClose, labelledBy, className = '' }: { children: ReactNode; onClose: () => void; labelledBy: string; className?: string }) {
  const ref = useRef<HTMLDivElement>(null)
  const closeRef = useRef(onClose)
  closeRef.current = onClose
  useEffect(() => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const timer = window.setTimeout(() => {
      const target = ref.current?.querySelector<HTMLElement>('[data-autofocus], button:not([disabled]), input:not([disabled]), [tabindex="0"]')
      target?.focus()
    }, 0)
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { event.preventDefault(); closeRef.current(); return }
      if (event.key !== 'Tab' || !ref.current) return
      const items = Array.from(ref.current.querySelectorAll<HTMLElement>('a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex="0"]')).filter((item) => !item.hasAttribute('hidden'))
      if (!items.length) { event.preventDefault(); return }
      const first = items[0]
      const last = items[items.length - 1]
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
    }
    document.addEventListener('keydown', handleKey)
    return () => { window.clearTimeout(timer); document.removeEventListener('keydown', handleKey); document.body.style.overflow = previousOverflow; previous?.focus() }
  }, [])
  return createPortal(<div className="dialog-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
    <div ref={ref} className={className} role="dialog" aria-modal="true" aria-labelledby={labelledBy}>{children}</div>
  </div>, document.body)
}

export function ConfirmDialog({ title, description, confirmLabel, onConfirm, onClose, loading = false }: { title: string; description: string; confirmLabel: string; onConfirm: () => void; onClose: () => void; loading?: boolean }) {
  return <Dialog labelledBy="confirm-title" onClose={onClose} className="modal">
    <div className="modal-heading"><h2 id="confirm-title">{title}</h2><button className="icon-button" onClick={onClose} aria-label="Close"><X size={15} /></button></div>
    <p>{description}</p>
    <div className="modal-actions"><Button onClick={onClose}>Cancel</Button><Button variant="primary" loading={loading} onClick={onConfirm}>{confirmLabel}</Button></div>
  </Dialog>
}
