import type { ComponentProps } from 'react'
import { cn } from '@/lib/utils'

export const buttonClass = (variant: 'primary' | 'secondary' | 'ghost' = 'secondary') =>
  cn(
    'action-control inline-flex min-h-11 items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-sm font-medium transition duration-300 active:scale-[.98] disabled:cursor-not-allowed disabled:opacity-40 disabled:active:scale-100 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-accent',
    variant === 'primary'
      ? 'border border-brand bg-brand text-white shadow-[0_3px_16px_#c9323c15] hover:border-[#e44952] hover:bg-[#dc3c46] hover:shadow-[0_6px_24px_#c9323c25]'
      : variant === 'ghost'
        ? 'text-muted hover:bg-white/5 hover:text-white'
        : 'border border-white/15 bg-white/4 text-white backdrop-blur-sm hover:border-white/30 hover:bg-white/8',
  )
export function Button({
  className,
  variant,
  ...props
}: ComponentProps<'button'> & { variant?: 'primary' | 'secondary' | 'ghost' }) {
  return <button className={cn(buttonClass(variant), className)} {...props} />
}
