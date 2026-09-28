'use client'
import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { AnimatePresence, motion, useMotionValueEvent, useScroll } from 'motion/react'
import { ArrowLeft, ArrowUpRight, Menu, X, MoveRight } from 'lucide-react'
import { Brand } from './brand'
import { Button, buttonClass } from './ui/button'
import { cn } from '@/lib/utils'

const landingLinks = [
  { label: 'Platform', id: 'platform' },
  { label: 'Detection', id: 'detection' },
  { label: 'How it works', id: 'architecture' },
]
const monitorLinks = [
  { label: 'Overview', id: 'overview' },
  { label: 'Traffic replay', id: 'replay' },
  { label: 'Detection coverage', id: 'coverage' },
  { label: 'Alert stream', id: 'alerts' },
]

export function SiteNav({ monitor = false }: { monitor?: boolean }) {
  const links = monitor ? monitorLinks : landingLinks
  const base = monitor ? '/monitor' : '/'
  const [active, setActive] = useState(monitor ? 'overview' : '')
  const [open, setOpen] = useState(false)
  const [scrolled, setScrolled] = useState(false)
  const toggle = useRef<HTMLButtonElement>(null)
  const header = useRef<HTMLElement>(null)
  const { scrollY } = useScroll()
  useMotionValueEvent(scrollY, 'change', (value) => setScrolled(value > 24))
  useEffect(() => {
    const sync = () => {
      const hash = window.location.hash.slice(1)
      if (links.some((link) => link.id === hash)) setActive(hash)
    }
    sync()
    window.addEventListener('hashchange', sync)
    const visible = new Set<Element>()
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) visible.add(entry.target)
          else visible.delete(entry.target)
        })
        const closest = [...visible].sort(
          (a, b) =>
            Math.abs(a.getBoundingClientRect().top - 150) -
            Math.abs(b.getBoundingClientRect().top - 150),
        )[0]
        if (closest) setActive(closest.id)
        else if (!monitor && window.scrollY < 300) setActive('')
      },
      { rootMargin: '-130px 0px -45% 0px', threshold: [0, 0.1, 0.5] },
    )
    links.forEach(({ id }) => {
      const node = document.getElementById(id)
      if (node) observer.observe(node)
    })
    return () => {
      observer.disconnect()
      window.removeEventListener('hashchange', sync)
    }
  }, [links, monitor])
  useEffect(() => {
    if (!open) return
    const close = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false)
        toggle.current?.focus()
      }
    }
    const outside = (event: PointerEvent) => {
      if (event.target instanceof Node && !header.current?.contains(event.target)) setOpen(false)
    }
    window.addEventListener('keydown', close)
    window.addEventListener('pointerdown', outside)
    return () => {
      window.removeEventListener('keydown', close)
      window.removeEventListener('pointerdown', outside)
    }
  }, [open])
  return (
    <motion.header
      ref={header}
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45 }}
      className={cn(
        'sticky top-0 z-50 border-b border-white/8 bg-ink/85 backdrop-blur-xl transition-shadow',
        scrolled && 'shadow-[0_8px_30px_#00000040]',
      )}
    >
      <div className="mx-auto flex h-20 max-w-[1440px] items-center justify-between gap-3 px-5 sm:px-8 lg:px-12">
        <Brand className="max-[360px]:gap-1.5 max-[360px]:text-[22px]" />
        <nav
          aria-label={monitor ? 'Monitor navigation' : 'Main navigation'}
          className="hidden items-center gap-1 xl:flex"
        >
          {links.map(({ label, id }) => (
            <Link
              key={id}
              href={`${base}#${id}`}
              onClick={() => setActive(id)}
              aria-current={active === id ? 'location' : undefined}
              className={cn(
                'relative rounded-full px-4 py-3 text-[11px] transition-colors hover:text-white',
                active === id ? 'text-white' : 'text-muted',
              )}
            >
              {active === id && (
                <motion.span
                  layoutId="navigation-active"
                  className="absolute inset-0 rounded-full border border-brand/25 bg-brand/8"
                  transition={{ type: 'spring', stiffness: 380, damping: 32 }}
                />
              )}
              <span className="relative">{label}</span>
            </Link>
          ))}
        </nav>
        <div className="flex items-center gap-2 sm:gap-3">
          {monitor && (
            <a
              href="/docs"
              target="_blank"
              rel="noopener noreferrer"
              className="hidden min-h-11 items-center gap-1.5 text-[11px] text-muted transition hover:text-white xl:flex"
            >
              API reference <ArrowUpRight size={13} />
            </a>
          )}
          <Link
            href={monitor ? '/' : '/monitor'}
            className={cn(
              buttonClass('secondary'),
              'hidden rounded-full px-4 text-[11px] min-[420px]:inline-flex',
            )}
          >
            {monitor ? (
              <>
                <ArrowLeft size={13} /> Back to platform
              </>
            ) : (
              <>
                Open monitor <ArrowUpRight size={14} />
              </>
            )}
          </Link>
          <Button
            ref={toggle}
            variant="ghost"
            aria-label={open ? 'Close menu' : 'Open menu'}
            aria-expanded={open}
            aria-controls="mobile-navigation"
            className="w-11 p-2 xl:hidden"
            onClick={() => setOpen(!open)}
          >
            {open ? <X size={20} /> : <Menu size={20} />}
          </Button>
        </div>
      </div>
      <AnimatePresence>
        {open && (
          <motion.nav
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            id="mobile-navigation"
            aria-label="Mobile navigation"
            className="absolute inset-x-0 top-full max-h-[calc(100dvh-145px)] overflow-y-auto border-y border-line bg-ink/98 shadow-2xl backdrop-blur-xl xl:hidden"
          >
            <div className="mx-auto flex max-w-[1440px] flex-col gap-1 px-5 py-4 sm:px-8">
              {links.map(({ label, id }) => (
                <Link
                  key={id}
                  href={`${base}#${id}`}
                  aria-current={active === id ? 'location' : undefined}
                  onClick={() => {
                    setActive(id)
                    setOpen(false)
                  }}
                  className={cn(
                    'rounded-xl px-4 py-3 text-sm transition hover:bg-white/5',
                    active === id ? 'bg-brand/10 text-white' : 'text-muted',
                  )}
                >
                  {label}
                </Link>
              ))}
              <div className="mt-2 flex flex-wrap gap-3 border-t border-line pt-4">
                <Link
                  href={monitor ? '/' : '/monitor'}
                  onClick={() => setOpen(false)}
                  className={cn(buttonClass('secondary'), 'text-xs')}
                >
                  {monitor ? 'Back to platform' : 'Open monitor'} <ArrowUpRight size={13} />
                </Link>
                <a
                  href="/docs"
                  target="_blank"
                  rel="noopener noreferrer"
                  className={cn(buttonClass('ghost'), 'text-xs')}
                >
                  API reference <ArrowUpRight size={13} />
                </a>
              </div>
            </div>
          </motion.nav>
        )}
      </AnimatePresence>
      {monitor && (
        <div className="border-t border-white/5 bg-white/[.015]">
          <div className="mx-auto flex min-h-9 max-w-[1440px] flex-wrap items-center justify-between gap-x-4 gap-y-1 px-5 py-2 text-[9px] tracking-[.1em] sm:px-8 lg:px-12">
            <span className="text-muted">
              UNIVECT <span className="mx-2 text-line">/</span>{' '}
              <span className="text-white">MONITOR</span>
            </span>
            <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-muted">
              <MoveRight size={13} className="text-accent" />
              <span className="text-white">Passive sensor</span>
              <span>Read-only · Metadata only · No response path</span>
            </span>
          </div>
        </div>
      )}
    </motion.header>
  )
}
