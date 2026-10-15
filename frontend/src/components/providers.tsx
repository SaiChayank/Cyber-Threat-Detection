'use client'
import { MotionConfig } from 'motion/react'
import * as Tooltip from '@radix-ui/react-tooltip'
import type { ReactNode } from 'react'
import { easeOut } from '@/lib/motion'
import { useReducedMotion } from '@/hooks/use-reduced-motion'

export function Providers({ children }: { children: ReactNode }) {
  const reducedMotion = useReducedMotion()
  return (
    <MotionConfig
      reducedMotion={reducedMotion ? 'always' : 'never'}
      transition={{ duration: reducedMotion ? 0 : 0.45, ease: easeOut }}
    >
      <Tooltip.Provider delayDuration={250}>{children}</Tooltip.Provider>
    </MotionConfig>
  )
}
