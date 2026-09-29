'use client'
import { motion, useReducedMotion } from 'motion/react'
import type { ReactNode } from 'react'
import { easeOut } from '@/lib/motion'
export function Reveal({
  children,
  delay = 0,
  className,
}: {
  children: ReactNode
  delay?: number
  className?: string
}) {
  const reducedMotion = useReducedMotion()
  return (
    <motion.div
      initial={reducedMotion ? false : { opacity: 0, y: 18 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.05 }}
      transition={{
        duration: reducedMotion ? 0 : 0.65,
        delay: reducedMotion ? 0 : delay,
        ease: easeOut,
      }}
      className={className}
    >
      {children}
    </motion.div>
  )
}
