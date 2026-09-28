import { cn } from '@/lib/utils'
const colors: Record<string, string> = {
  CRITICAL: 'border-brand/50 bg-brand/25 text-white',
  HIGH: 'border-brand/30 bg-brand/10 text-accent',
  MEDIUM: 'border-white/20 bg-white/5 text-signal',
  LOW: 'border-line bg-white/2 text-muted',
}
export function Severity({ severity }: { severity: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[9px] font-semibold tracking-[.04em]',
        colors[severity] || 'border-line text-muted',
      )}
    >
      <span className="h-1 w-1 rounded-full bg-current" />
      {severity}
    </span>
  )
}
