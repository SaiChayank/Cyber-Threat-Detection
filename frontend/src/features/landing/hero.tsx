'use client'
import Link from 'next/link'
import { motion, useReducedMotion } from 'motion/react'
import {
  ArrowRight,
  ArrowDown,
  Fingerprint,
  FileCode2,
  LockKeyhole,
  Waves,
  Network,
  ShieldCheck,
} from 'lucide-react'
import { SceneView } from '@/components/scene-view'
import { buttonClass } from '@/components/ui/button'
import { useHealth } from '@/hooks/use-health'
import { cn } from '@/lib/utils'
import { easeOut } from '@/lib/motion'

export function Hero() {
  const health = useHealth()
  const reducedMotion = useReducedMotion()
  return (
    <>
      <section
        className="relative mx-auto grid max-w-[1440px] items-center px-5 pt-12 pb-8 sm:px-8 md:min-h-[680px] md:grid-cols-[.95fr_1.05fr] md:pt-10 lg:px-14 lg:pt-8"
        aria-labelledby="hero-heading"
      >
        <motion.div
          initial={reducedMotion ? false : { opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: reducedMotion ? 0 : 0.65 }}
          className="relative z-10"
        >
          <div className="mb-7 inline-flex items-center gap-2.5 rounded-full border border-line bg-panel px-3 py-2 text-[9px] tracking-[.14em] text-muted uppercase">
            <span className="h-1.5 w-1.5 rounded-full bg-accent" />
            Univect / Passive network intelligence
          </div>
          <h1
            id="hero-heading"
            className="font-display text-[clamp(47px,7.1vw,103px)] leading-[.97] font-medium tracking-[-.065em]"
          >
            {['Threats move.', 'See them', 'clearly.'].map((line, index) => (
              <span key={line} className="block overflow-hidden pb-1">
                <motion.span
                  className={cn('block', index === 2 && 'text-accent')}
                  initial={reducedMotion ? false : { y: '105%' }}
                  animate={{ y: 0 }}
                  transition={{
                    duration: reducedMotion ? 0 : 0.85,
                    delay: reducedMotion ? 0 : 0.12 + index * 0.08,
                    ease: easeOut,
                  }}
                >
                  {line}
                  {index < 2 ? ' ' : ''}
                </motion.span>
              </span>
            ))}
          </h1>
          <p className="mt-7 max-w-[355px] text-sm leading-7 text-muted lg:text-[15px]">
            One-way traffic. Deeper insight.
            <br />
            Turn one-way traffic into streaming detections, meaningful evidence and a clearer
            picture.
          </p>
          <motion.div
            initial={reducedMotion ? false : { opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: reducedMotion ? 0 : 0.6, delay: reducedMotion ? 0 : 0.4 }}
            className="mt-8 flex flex-wrap items-center gap-5"
          >
            <Link
              href="/monitor"
              className={cn(buttonClass('primary'), 'group rounded-full px-6 py-3.5')}
            >
              Enter the monitor <ArrowUpRightIcon />
            </Link>
            <Link
              href="/#architecture"
              className="inline-flex min-h-11 items-center gap-2 text-xs text-muted hover:text-white"
            >
              Explore the pipeline <ArrowDown size={14} />
            </Link>
          </motion.div>
          <div className="mt-7 flex flex-wrap gap-x-5 gap-y-2 text-[10px] text-muted">
            <span className="inline-flex items-center gap-1.5">
              <ShieldCheck size={12} className="text-accent" />
              Read-only by design
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span
                className={cn(
                  'h-1.5 w-1.5 rounded-full',
                  health === 'online'
                    ? 'bg-signal'
                    : health === 'offline'
                      ? 'bg-accent'
                      : 'bg-muted',
                )}
              />
              {health === 'online'
                ? 'Local API connected'
                : health === 'offline'
                  ? 'Local API unavailable'
                  : 'Checking local API'}
            </span>
          </div>
        </motion.div>
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 1, delay: 0.1 }}
          className="relative mt-7 h-[340px] sm:h-[470px] md:-ml-8 md:mt-0 md:h-[580px] lg:-mr-7"
        >
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_55%_48%,#b8232c18,transparent_65%)]"
          />
          <span className="absolute top-10 left-5 z-10 text-[9px] tracking-[.15em] text-muted uppercase md:top-12">
            Signal in. Insight out.
          </span>
          <SceneView mode="pipeline" controls className="h-full w-full" />
          <div className="pointer-events-none absolute right-3 bottom-20 z-10 rounded-xl border border-accent/15 bg-panel/75 px-4 py-3 text-[10px] backdrop-blur-md sm:right-10">
            <span className="mb-1.5 block text-[8px] tracking-[.15em] text-muted uppercase">
              Analysis boundary
            </span>
            <span className="flex items-center gap-2 text-accent">
              <LockKeyhole size={12} /> Metadata only
            </span>
          </div>
        </motion.div>
      </section>
      <div className="mx-auto flex max-w-[1440px] flex-col justify-between gap-3 px-5 pb-7 text-[9px] tracking-[.13em] text-muted uppercase sm:flex-row sm:px-8 lg:px-14">
        <span>
          PS26145 <span className="mx-3 text-line">/</span> National Technical Research Organisation
        </span>
        <span>Built to observe. Designed to explain.</span>
      </div>
      <div className="border-y border-line/70 bg-panel/35">
        <div className="mx-auto flex max-w-[1328px] flex-wrap items-center justify-between gap-x-5 gap-y-5 px-5 py-7 text-[11px] text-muted sm:px-8">
          <span className="text-[9px] tracking-[.14em] uppercase">One-way inputs</span>
          {[
            { icon: FileCode2, label: 'PCAP captures' },
            { icon: Network, label: 'Flow records' },
            { icon: Waves, label: 'DNS queries' },
            { icon: Fingerprint, label: 'TLS fingerprints' },
            { icon: LockKeyhole, label: 'QUIC metadata' },
          ].map(({ icon: Icon, label }) => (
            <span key={label} className="flex items-center gap-2">
              <Icon size={16} strokeWidth={1.4} />
              {label}
            </span>
          ))}
        </div>
      </div>
    </>
  )
}
function ArrowUpRightIcon() {
  return (
    <ArrowRight
      size={16}
      className="-rotate-45 transition-transform duration-300 group-hover:translate-x-0.5 group-hover:-translate-y-0.5"
    />
  )
}
