import type { ButtonHTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

export const buttonClass = (variant: 'primary' | 'secondary' | 'ghost' = 'secondary') =>
  cn(
    'inline-flex min-h-11 items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold transition duration-200 disabled:cursor-not-allowed disabled:opacity-40 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-lilac',
    variant === 'primary'
      ? 'bg-lime text-ink hover:bg-[#e2ffcd] hover:shadow-[0_0_24px_#d5f5bd20]'
      : variant === 'ghost'
        ? 'text-muted hover:bg-white/5 hover:text-white'
        : 'border border-line bg-panel text-white hover:border-lilac/50 hover:bg-lilac/10',
  )
export function Button({
  className,
  variant,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'ghost' }) {
  return <button className={cn(buttonClass(variant), className)} {...props} />
}
