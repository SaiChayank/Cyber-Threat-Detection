import Link from 'next/link'
import { cn } from '@/lib/utils'

export function BrandMark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 40 40"
      fill="none"
      aria-hidden="true"
      className={cn('h-9 w-9 shrink-0', className)}
    >
      <path
        d="M8 8v18a10 10 0 0 0 20 0v-5"
        stroke="currentColor"
        strokeWidth="5"
        strokeLinecap="square"
      />
      <path d="m19 19 13-13M22 6h10v10" stroke="#c9323c" strokeWidth="5" strokeLinejoin="miter" />
    </svg>
  )
}
export function Brand({ compact = false, className }: { compact?: boolean; className?: string }) {
  return (
    <Link
      href="/"
      aria-label="Univect home"
      className={cn(
        'inline-flex items-center gap-2.5 font-display text-[23px] font-medium tracking-[-.05em] text-white',
        className,
      )}
    >
      <BrandMark />
      <span>
        univect<span className="text-accent">.</span>
        {compact && (
          <span className="mt-1 block font-sans text-[9px] tracking-[.15em] text-muted">
            ONE-WAY INTELLIGENCE
          </span>
        )}
      </span>
    </Link>
  )
}
