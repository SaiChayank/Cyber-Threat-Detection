'use client'
import * as Tabs from '@radix-ui/react-tabs'
import { motion } from 'motion/react'
import Link from 'next/link'
import { ArrowRight, Fingerprint } from 'lucide-react'
import { threats } from '@/constants/threats'
import { Eyebrow } from '@/components/ui/panel'
import { buttonClass } from '@/components/ui/button'

export function Detection() {
  return (
    <section id="detection" className="border-y border-line/70 bg-panel/30">
      <div className="mx-auto max-w-[1328px] px-5 py-20 sm:px-8 md:py-24">
        <div className="mb-10 flex flex-col justify-between gap-4 md:flex-row md:items-end">
          <div>
            <Eyebrow className="text-accent">Six threat categories. A wider perspective.</Eyebrow>
            <h2 className="mt-4 font-display text-[clamp(34px,4.5vw,54px)] leading-[1.1] tracking-[-.05em]">
              Small clues.
              <br />
              Significant signals.
            </h2>
          </div>
          <p className="max-w-[350px] text-sm leading-7 text-muted">
            From sudden surges to quiet, repeating connections. Explore the signals our detection
            modules observe.
          </p>
        </div>
        <Tabs.Root defaultValue="DDOS" orientation="horizontal">
          <Tabs.List
            aria-label="Detection categories"
            className="mb-5 grid grid-cols-2 gap-2 md:grid-cols-3 lg:grid-cols-6"
          >
            {threats.map(({ id, icon: Icon, name }) => (
              <Tabs.Trigger
                key={id}
                value={id}
                className="flex min-h-13 items-center justify-center gap-2 rounded-xl border border-line bg-panel px-2 text-[11px] text-muted transition hover:border-accent/40 hover:text-white focus-visible:outline-2 focus-visible:outline-accent data-[state=active]:border-accent/50 data-[state=active]:bg-accent/12 data-[state=active]:text-accent"
              >
                <Icon size={16} />
                {name}
              </Tabs.Trigger>
            ))}
          </Tabs.List>
          {threats.map(({ id, title, description, signals, icon: Icon }) => (
            <Tabs.Content
              key={id}
              value={id}
              className="focus-visible:outline-2 focus-visible:outline-accent"
            >
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.25 }}
                className="relative grid overflow-hidden rounded-3xl border border-line bg-ink p-7 md:min-h-80 md:grid-cols-[1.3fr_1fr] md:p-12"
              >
                <div className="relative z-10">
                  <Icon size={28} className="mb-6 text-accent" strokeWidth={1.5} />
                  <h3 className="font-display text-3xl tracking-[-.04em]">{title}</h3>
                  <p className="mt-4 max-w-[490px] text-sm leading-7 text-muted">{description}</p>
                  <div className="mt-6 flex flex-wrap gap-2">
                    {signals.map((signal) => (
                      <span
                        className="rounded-full border border-line px-3 py-2 text-[10px] text-accent/80"
                        key={signal}
                      >
                        {signal}
                      </span>
                    ))}
                  </div>
                </div>
                <div
                  aria-hidden="true"
                  className="relative hidden items-center justify-center md:flex"
                >
                  <div className="radar-orbit signal-scan absolute h-64 w-64 border-t-brand/70" />
                  <div className="radar-orbit absolute h-46 w-46" />
                  <div className="radar-orbit absolute h-28 w-28 bg-accent/3" />
                  <Fingerprint size={52} strokeWidth={0.8} className="text-accent/80" />
                  <div className="absolute top-10 right-20 h-2 w-2 rounded-full bg-accent shadow-[0_0_14px_#c9323c50]" />
                  <div className="absolute bottom-8 left-20 h-1.5 w-1.5 rounded-full bg-accent" />
                </div>
              </motion.div>
            </Tabs.Content>
          ))}
        </Tabs.Root>
        <div className="mt-6 flex flex-col justify-between gap-3 text-[11px] text-muted sm:flex-row">
          <span>
            Research prototype · Scores indicate suspicion and require analyst interpretation.
          </span>
          <Link
            href="/monitor#coverage"
            className="flex min-h-8 items-center gap-2 text-accent hover:text-white"
          >
            View detection coverage <ArrowRight size={13} />
          </Link>
        </div>
      </div>
    </section>
  )
}
export function Architecture() {
  const steps = [
    {
      title: 'Observe',
      body: 'Receive mirrored traffic, capture files or exported flow metadata.',
    },
    { title: 'Extract', body: 'Build bounded, causal features from what was passively observed.' },
    { title: 'Score', body: 'Apply trained models and rules to classify suspicious patterns.' },
    {
      title: 'Explain',
      body: 'Stream standardized alerts with severity, confidence and evidence.',
    },
  ]
  return (
    <section id="architecture" className="mx-auto max-w-[1328px] px-5 py-20 sm:px-8 md:py-28">
      <Eyebrow className="text-accent">How it works</Eyebrow>
      <div className="mt-4 flex flex-col justify-between gap-4 md:flex-row md:items-end">
        <h2 className="font-display text-[clamp(34px,4.5vw,54px)] leading-[1.1] tracking-[-.05em]">
          One direction.
          <br />
          More understanding.
        </h2>
        <p className="max-w-[340px] text-sm leading-7 text-muted">
          Intelligence belongs in the monitoring enclave. Every step respects the collection
          boundary.
        </p>
      </div>
      <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {steps.map((step, index) => (
          <motion.article
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.4, delay: index * 0.08 }}
            key={step.title}
            className="border-t border-line pt-5"
          >
            <div className="flex items-center justify-between text-[11px] text-accent">
              <span>0{index + 1}</span>
              {index < 3 && <ArrowRight size={15} className="text-muted" />}
            </div>
            <h3 className="mt-7 font-display text-xl">{step.title}</h3>
            <p className="mt-3 text-xs leading-6 text-muted">{step.body}</p>
          </motion.article>
        ))}
      </div>
      <p className="mt-10 rounded-xl border border-line bg-panel px-5 py-4 text-xs leading-6 text-muted">
        Read-only ingest <span className="mx-3 text-line">/</span> No source queries{' '}
        <span className="mx-3 text-line">/</span> No inline blocking{' '}
        <span className="mx-3 text-line">/</span> No payload decryption
      </p>
      <div className="relative mt-20 overflow-hidden rounded-[28px] border border-accent/20 bg-[radial-gradient(ellipse_at_80%_50%,#8f22252a,transparent_60%)] px-7 py-12 sm:px-12">
        <div className="relative z-10 flex flex-col justify-between gap-8 md:flex-row md:items-center">
          <div>
            <Eyebrow className="text-accent">The next signal is waiting</Eyebrow>
            <h2 className="mt-4 font-display text-4xl tracking-[-.055em] sm:text-5xl">
              Meet your new lookout.
            </h2>
            <p className="mt-4 text-sm text-muted">
              Replay traffic. Follow the evidence. See the bigger picture.
            </p>
          </div>
          <Link href="/monitor" className={buttonClass('primary')}>
            Open threat monitor <ArrowRight size={16} />
          </Link>
        </div>
      </div>
    </section>
  )
}
