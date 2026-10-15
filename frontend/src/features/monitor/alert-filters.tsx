'use client'
import { Search, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { detectionModules } from '@/constants/threats'

export function AlertFilters({
  search,
  threat,
  severity,
  engine,
  engines,
  onSearch,
  onThreat,
  onSeverity,
  onEngine,
  onReset,
}: {
  search: string
  threat: string
  severity: string
  engine: string
  engines: string[]
  onSearch: (value: string) => void
  onThreat: (value: string) => void
  onSeverity: (value: string) => void
  onEngine: (value: string) => void
  onReset: () => void
}) {
  return (
    <div className="space-y-3">
      <div className="grid gap-2 rounded-xl border border-white/6 bg-ink/40 p-2 sm:grid-cols-3 xl:grid-cols-[minmax(0,1fr)_170px_145px_145px]">
        <div className="relative sm:col-span-3 xl:col-span-1">
          <Search size={14} aria-hidden="true" className="absolute top-3.5 left-3 text-muted" />
          <input
            type="search"
            aria-label="Search alerts"
            placeholder="Search IP, flow ID or evidence…"
            value={search}
            onChange={(event) => onSearch(event.target.value)}
            className="min-h-11 w-full rounded-xl border border-line bg-ink pr-3 pl-9 text-xs placeholder:text-muted/70"
          />
        </div>
        <select
          aria-label="Filter threat class"
          value={threat}
          onChange={(event) => onThreat(event.target.value)}
          className="min-h-11 min-w-0 rounded-xl border border-line bg-ink px-3 text-xs"
        >
          <option value="">All threats</option>
          {detectionModules.map((item) => (
            <option key={item.id} value={item.id}>
              {item.name}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter severity"
          value={severity}
          onChange={(event) => onSeverity(event.target.value)}
          className="min-h-11 min-w-0 rounded-xl border border-line bg-ink px-3 text-xs"
        >
          <option value="">All severities</option>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((item) => (
            <option key={item}>{item}</option>
          ))}
        </select>
        <select
          aria-label="Filter detection engine"
          value={engine}
          onChange={(event) => onEngine(event.target.value)}
          className="min-h-11 min-w-0 rounded-xl border border-line bg-ink px-3 text-xs"
        >
          <option value="">All engines</option>
          {engines.map((item) => (
            <option key={item}>{item}</option>
          ))}
        </select>
      </div>
      {!!(search || threat || severity || engine) && (
        <div className="flex flex-wrap items-center justify-between gap-2 text-[10px] text-muted">
          <span>Filters apply together to loaded records.</span>
          <Button variant="ghost" className="min-h-9 px-3 text-[10px]" onClick={onReset}>
            <X size={12} aria-hidden="true" /> Clear filters
          </Button>
        </div>
      )}
    </div>
  )
}
