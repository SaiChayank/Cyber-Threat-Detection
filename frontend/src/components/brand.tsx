import Link from 'next/link'
import { cn } from '@/lib/utils'

export function Brand({ compact = false, className }: { compact?: boolean; className?: string }) {
  return (
    <Link
      href="/"
      aria-label="Sentinel home"
      className={cn(
        'inline-flex items-center gap-2.5 font-display text-[27px] font-semibold tracking-[-.06em] text-white',
        className,
      )}
    >
      <svg
        width="30"
        height="34"
        viewBox="0 0 30 34"
        fill="none"
        aria-hidden="true"
        className="shrink-0"
      >
        <path d="M15 1 28 8.5v16L15 32 2 24.5v-16L15 1Z" stroke="#a67bfa" strokeWidth="2" />
        <path d="M9 10h12v4H13v3h8v7H9v-4h8v-3H9v-7Z" fill="#a67bfa" />
      </svg>
      <span>
        sentinel.
        <span
          className={cn(
            'mt-1 block font-sans text-[9px] tracking-[.18em] text-muted',
            !compact && 'hidden',
          )}
        >
          PS26145 · NTRO
        </span>
      </span>
    </Link>
  )
}
