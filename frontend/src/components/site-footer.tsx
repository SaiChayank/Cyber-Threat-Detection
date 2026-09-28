'use client'
import Link from 'next/link'
import { motion } from 'motion/react'
import { ArrowUpRight, Github, MoveRight } from 'lucide-react'
import { Brand } from './brand'

export function SiteFooter() {
  return (
    <footer className="relative border-t border-white/8 bg-[#0c0d0d]">
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.45 }}
        className="mx-auto max-w-[1440px] px-5 pt-12 sm:px-8 lg:px-12"
      >
        <div className="grid gap-10 pb-10 sm:grid-cols-[1.5fr_1fr_1fr]">
          <div>
            <Brand />
            <p className="mt-5 max-w-80 text-sm leading-7 text-muted">
              One-way traffic. Deeper insight.
              <br />
              Passive threat intelligence with evidence at its core.
            </p>
            <span className="mt-5 inline-flex items-center gap-2 text-[10px] tracking-[.08em] text-muted">
              <MoveRight size={14} className="text-accent" /> PS26145 · Research prototype
            </span>
          </div>
          <nav aria-label="Footer navigation" className="space-y-3 text-xs">
            <p className="mb-5 text-[9px] tracking-[.16em] text-muted uppercase">Explore</p>
            {[
              ['Platform', '/#platform'],
              ['Detection', '/#detection'],
              ['How it works', '/#architecture'],
              ['Threat monitor', '/monitor'],
            ].map(([label, href]) => (
              <Link
                key={href}
                href={href}
                className="block w-fit py-1 transition hover:text-accent"
              >
                {label}
              </Link>
            ))}
          </nav>
          <div className="space-y-3 text-xs">
            <p className="mb-5 text-[9px] tracking-[.16em] text-muted uppercase">
              Project & resources
            </p>
            <a
              href="https://github.com/SaiChayank/Cyber-Threat-Detection"
              target="_blank"
              rel="noopener noreferrer"
              className="flex min-h-8 w-fit items-center gap-2 transition hover:text-accent"
            >
              <Github size={14} /> Source repository <ArrowUpRight size={12} />
            </a>
            <a
              href="/docs"
              target="_blank"
              rel="noopener noreferrer"
              className="flex min-h-8 w-fit items-center gap-2 transition hover:text-accent"
            >
              API reference <ArrowUpRight size={12} />
            </a>
            <a
              href="https://github.com/SaiChayank/Cyber-Threat-Detection/issues"
              target="_blank"
              rel="noopener noreferrer"
              className="flex min-h-8 w-fit items-center gap-2 transition hover:text-accent"
            >
              Report an issue <ArrowUpRight size={12} />
            </a>
          </div>
        </div>
        <div className="flex flex-wrap justify-between gap-3 border-t border-white/8 py-6 text-[10px] leading-5 text-muted">
          <span>© {new Date().getFullYear()} Univect · Project by SaiChayank</span>
          <span>Read-only observation · No inline blocking · No payload decryption</span>
        </div>
      </motion.div>
    </footer>
  )
}
