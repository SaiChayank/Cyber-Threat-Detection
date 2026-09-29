'use client'
import { MotionConfig } from 'motion/react'
import * as Tooltip from '@radix-ui/react-tooltip'
import type { ReactNode } from 'react'
import { easeOut } from '@/lib/motion'

export function Providers({ children }: { children: ReactNode }) {
  return (
    <MotionConfig reducedMotion="user" transition={{ duration: 0.45, ease: easeOut }}>
      <Tooltip.Provider delayDuration={250}>{children}</Tooltip.Provider>
    </MotionConfig>
  )
}
