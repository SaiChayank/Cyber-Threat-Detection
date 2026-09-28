import { Brand } from '@/components/brand'
import { LandingHeader } from './header'
import { Hero } from './hero'
import { Platform } from './platform'
import { Architecture, Detection } from './detection'
import { ArrowUpRight } from 'lucide-react'

export function Landing() {
  return (
    <>
      <LandingHeader />
      <main id="main-content">
        <Hero />
        <Platform />
        <Detection />
        <Architecture />
      </main>
      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-[1328px] flex-col items-start justify-between gap-6 px-5 py-8 sm:flex-row sm:items-center sm:px-8">
          <Brand className="text-xl" />
          <p className="text-[10px] text-muted">PS26145 · Passive network threat intelligence</p>
          <a
            href="/docs"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex min-h-11 items-center gap-2 text-xs text-muted hover:text-white"
          >
            API reference <ArrowUpRight size={13} />
          </a>
        </div>
      </footer>
    </>
  )
}
