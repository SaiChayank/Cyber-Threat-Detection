import { cn } from '@/lib/utils'
const colors: Record<string, string> = {
  CRITICAL: 'border-rose-400/20 bg-rose-400/10 text-rose-300',
  HIGH: 'border-orange-400/20 bg-orange-400/10 text-orange-300',
  MEDIUM: 'border-amber-300/20 bg-amber-300/10 text-amber-200',
  LOW: 'border-lime/20 bg-lime/10 text-lime',
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
