'use client'
import * as Tooltip from '@radix-ui/react-tooltip'
import type { ReactNode } from 'react'

export function Hint({ children, text }: { children: ReactNode; text: string }) {
  return (
    <Tooltip.Root>
      <Tooltip.Trigger asChild>{children}</Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content
          sideOffset={8}
          className="z-100 max-w-72 rounded-xl border border-line bg-[#201a2d] px-3 py-2 text-xs text-white shadow-xl"
        >
          {text}
          <Tooltip.Arrow className="fill-[#201a2d]" />
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  )
}
