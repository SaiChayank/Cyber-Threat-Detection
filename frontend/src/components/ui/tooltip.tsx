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
          className="z-100 max-w-72 rounded-xl border border-white/15 bg-[#202222]/95 px-3 py-2 text-xs leading-5 text-white shadow-xl backdrop-blur-md"
        >
          {text}
          <Tooltip.Arrow className="fill-[#202222]" />
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  )
}
