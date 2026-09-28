'use client'
import { motion } from 'motion/react'
import { Radar, LockKeyhole, AudioLines, FileSearch } from 'lucide-react'
import { SceneView } from '@/components/scene-view'
import { Eyebrow } from '@/components/ui/panel'

const capabilities = [
  {
    title: 'Listen. Never interrupt.',
    body: 'A passive mirror feeds the enclave. The analytics layer has no response path to the monitored network.',
    icon: Radar,
  },
  {
    title: 'Let the patterns speak.',
    body: 'Causal features and model inference turn traffic rhythms, fan-out and metadata into useful signals.',
    icon: AudioLines,
  },
  {
    title: 'Keep encryption intact.',
    body: 'Inspect fingerprints, sizes and timing. Protected session content stays protected.',
    icon: LockKeyhole,
  },
  {
    title: 'Show your reasoning.',
    body: 'Every detection carries its severity, score, connection details and supporting evidence.',
    icon: FileSearch,
  },
]
export function Platform() {
  return (
    <section id="platform" className="mx-auto max-w-[1328px] px-5 py-20 sm:px-8 md:py-28">
      <div className="mx-auto max-w-2xl text-center">
        <Eyebrow className="text-accent">The observation layer</Eyebrow>
        <h2 className="mt-5 font-display text-[clamp(34px,4.5vw,56px)] leading-[1.08] tracking-[-.055em]">
          Eyes on the signal.
          <br />
          Hands off the network.
        </h2>
        <p className="mx-auto mt-5 max-w-[460px] text-sm leading-7 text-muted">
          Your network tells a story. Univect brings the clues together, without reaching back into
          production.
        </p>
      </div>
      <div className="mt-12 grid gap-4 md:grid-cols-[1fr_1.1fr_1fr] md:gap-6">
        <div className="order-2 grid gap-4 md:order-1">
          {capabilities.slice(0, 2).map((item, index) => (
            <Capability key={item.title} item={item} index={index} />
          ))}
        </div>
        <div className="relative order-1 min-h-[330px] md:order-2 md:min-h-[475px]">
          <div className="absolute inset-0 rounded-[40px] bg-[radial-gradient(ellipse_at_50%_55%,#9f23251a,transparent_65%)]" />
          <SceneView mode="agents" className="h-full min-h-[330px] md:min-h-[475px]" />
          <p className="absolute right-0 bottom-4 left-0 text-center text-[9px] tracking-[.18em] text-muted uppercase">
            Always curious. Strictly passive.
          </p>
        </div>
        <div className="order-3 grid gap-4">
          {capabilities.slice(2).map((item, index) => (
            <Capability key={item.title} item={item} index={index + 2} />
          ))}
        </div>
      </div>
    </section>
  )
}
function Capability({ item, index }: { item: (typeof capabilities)[number]; index: number }) {
  const Icon = item.icon
  return (
    <motion.article
      initial={{ opacity: 0, y: 15 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.3 }}
      transition={{ duration: 0.45, delay: index * 0.05 }}
      whileHover={{ y: -4 }}
      className="glass-panel flex min-h-52 flex-col rounded-[22px] p-6"
    >
      <div className="mb-7 flex items-center justify-between">
        <Icon size={23} strokeWidth={1.3} className="text-white/75" />
        <span className="font-display text-[10px] text-white/35">0{index + 1}</span>
      </div>
      <h3 className="font-display text-lg font-medium tracking-[-.03em]">{item.title}</h3>
      <p className="mt-3 text-xs leading-6 text-muted">{item.body}</p>
    </motion.article>
  )
}
