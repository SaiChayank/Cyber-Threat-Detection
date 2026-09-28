'use client'
import { useState } from 'react'
import Link from 'next/link'
import { AnimatePresence, motion } from 'motion/react'
import { ArrowUpRight, Menu, X } from 'lucide-react'
import { Brand } from '@/components/brand'
import { Button, buttonClass } from '@/components/ui/button'
import { cn } from '@/lib/utils'

const links = [
  { label: 'Platform', href: '/#platform' },
  { label: 'Detection', href: '/#detection' },
  { label: 'How it works', href: '/#architecture' },
]
export function LandingHeader() {
  const [open, setOpen] = useState(false)
  return (
    <header className="sticky top-0 z-40 border-b border-white/5 bg-ink/85 backdrop-blur-xl">
      <div className="mx-auto flex h-22 max-w-[1440px] items-center justify-between gap-3 px-5 sm:px-8 lg:px-14">
        <Brand className="max-[360px]:gap-1.5 max-[360px]:text-[23px]" />
        <nav
          aria-label="Main navigation"
          className="hidden items-center gap-8 text-xs text-muted md:flex"
        >
          {links.map((link) => (
            <Link key={link.label} href={link.href} className="py-3 transition hover:text-white">
              {link.label}
            </Link>
          ))}
        </nav>
        <div className="flex items-center gap-1.5 sm:gap-3">
          <Link
            href="/monitor"
            className={cn(
              buttonClass('secondary'),
              'min-h-10 rounded-full px-4 text-[11px] max-[360px]:px-2.5 max-[360px]:text-[10px]',
            )}
          >
            Open monitor <ArrowUpRight size={14} className="max-[360px]:hidden" />
          </Link>
          <Button
            variant="ghost"
            aria-label={open ? 'Close menu' : 'Open menu'}
            aria-expanded={open}
            aria-controls="mobile-navigation"
            className="w-11 p-2 md:hidden"
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
            className="overflow-hidden border-t border-line md:hidden"
            id="mobile-navigation"
            aria-label="Mobile navigation"
          >
            <div className="flex flex-col px-5 py-3">
              {links.map((link) => (
                <Link
                  key={link.label}
                  href={link.href}
                  className="rounded-lg px-3 py-3 text-sm text-muted hover:bg-white/5 hover:text-white"
                  onClick={() => setOpen(false)}
                >
                  {link.label}
                </Link>
              ))}
            </div>
          </motion.nav>
        )}
      </AnimatePresence>
    </header>
  )
}
