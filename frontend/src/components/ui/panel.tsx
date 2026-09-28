import type { HTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

export function Panel({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('glass-panel rounded-2xl', className)} {...props} />
}
export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden="true" className={cn('skeleton-surface rounded-md', className)} />
}
export function Eyebrow({
  children,
  className,
}: {
  children: React.ReactNode
  className?: string
}) {
  return (
    <p className={cn('text-[10px] font-semibold tracking-[.18em] text-muted uppercase', className)}>
      {children}
    </p>
  )
}
