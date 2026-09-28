'use client'
import { MotionConfig } from 'motion/react'
import * as Tooltip from '@radix-ui/react-tooltip'
import type { ReactNode } from 'react'

export function Providers({ children }: { children: ReactNode }) {
  return (
    <MotionConfig reducedMotion="user">
      <Tooltip.Provider delayDuration={250}>{children}</Tooltip.Provider>
    </MotionConfig>
  )
}
