'use client'
import { useEffect, useState } from 'react'
import Link from 'next/link'
import {
  LayoutDashboard,
  Play,
  Radar,
  ListFilter,
  ArrowUpRight,
  ArrowLeft,
  ShieldCheck,
  Menu,
  X,
} from 'lucide-react'
import { Brand } from '@/components/brand'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

const links = [
  { icon: LayoutDashboard, title: 'Overview', id: 'overview' },
  { icon: Play, title: 'Traffic replay', id: 'replay' },
  { icon: Radar, title: 'Detection coverage', id: 'coverage' },
  { icon: ListFilter, title: 'Alert stream', id: 'alerts' },
]
export function MonitorNav() {
  const [active, setActive] = useState('overview')
  const [open, setOpen] = useState(false)
  useEffect(() => {
    const synchronize = () =>
      setActive(
        links.some((link) => `#${link.id}` === window.location.hash)
          ? window.location.hash.slice(1)
          : 'overview',
      )
    synchronize()
    window.addEventListener('hashchange', synchronize)
    return () => window.removeEventListener('hashchange', synchronize)
  }, [])
  useEffect(() => {
    if (!open) return
    const close = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', close)
    return () => window.removeEventListener('keydown', close)
  }, [open])
  return (
    <>
      <div className="sticky top-0 z-40 flex h-18 items-center justify-between border-b border-line bg-ink/95 px-5 backdrop-blur-xl lg:hidden">
        <Brand className="text-xl" />
        <Button
          variant="ghost"
          aria-label={open ? 'Close monitor menu' : 'Open monitor menu'}
          aria-expanded={open}
          aria-controls="monitor-navigation"
          onClick={() => setOpen(!open)}
        >
          {open ? <X size={20} /> : <Menu size={20} />}
        </Button>
      </div>
      {open && (
        <button
          aria-label="Close navigation overlay"
          className="fixed inset-0 z-40 bg-black/60 lg:hidden"
          onClick={() => setOpen(false)}
        />
      )}
      <aside
        id="monitor-navigation"
        className={cn(
          'fixed top-0 bottom-0 left-0 z-50 flex w-[238px] flex-col border-r border-line bg-[#0c0912] px-5 py-8 transition-transform lg:translate-x-0',
          open ? 'visible translate-x-0' : 'invisible -translate-x-full lg:visible',
        )}
      >
        <Brand compact />
        <div className="mt-12 mb-3 px-3 text-[9px] tracking-[.18em] text-muted">MONITORING</div>
        <nav aria-label="Monitor navigation" className="space-y-1">
          {links.map(({ icon: Icon, title, id }) => (
            <Link
              key={id}
              href={`/monitor#${id}`}
              onClick={() => {
                setActive(id)
                setOpen(false)
              }}
              className={cn(
                'flex min-h-11 items-center gap-3 rounded-xl px-3 text-xs transition hover:bg-white/5 hover:text-white',
                active === id ? 'bg-lilac/12 text-lilac' : 'text-muted',
              )}
              aria-current={active === id ? 'location' : undefined}
            >
              <Icon size={16} />
              {title}
            </Link>
          ))}
        </nav>
        <div className="mt-9 mb-3 px-3 text-[9px] tracking-[.18em] text-muted">RESOURCES</div>
        <a
          href="/docs"
          target="_blank"
          rel="noopener noreferrer"
          className="flex min-h-11 items-center gap-3 rounded-xl px-3 text-xs text-muted hover:bg-white/5 hover:text-white"
        >
          <ArrowUpRight size={16} />
          API reference
        </a>
        <Link
          href="/"
          className="mt-3 flex min-h-11 items-center gap-3 px-3 text-xs text-muted hover:text-lilac"
        >
          <ArrowLeft size={15} />
          Back to platform
        </Link>
        <div className="mt-auto rounded-xl border border-line bg-panel p-4">
          <div className="flex items-center gap-2 text-xs text-lime">
            <ShieldCheck size={15} />
            Passive sensor
          </div>
          <p className="mt-3 text-[10px] leading-5 text-muted">
            Read-only ingest
            <br />
            Metadata only · No response path
          </p>
        </div>
      </aside>
    </>
  )
}
