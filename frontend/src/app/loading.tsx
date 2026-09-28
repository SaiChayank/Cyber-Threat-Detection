import { Skeleton } from '@/components/ui/panel'
import { BrandMark } from '@/components/brand'
export default function Loading() {
  return (
    <main
      id="main-content"
      className="mx-auto max-w-7xl space-y-8 px-6 py-16"
      aria-label="Loading Univect interface"
    >
      <div role="status" className="flex items-center gap-3 text-sm text-muted">
        <BrandMark /> Loading your observation layer…
      </div>
      <Skeleton className="h-10 w-52" />
      <Skeleton className="h-48 w-full" />
      <div className="grid grid-cols-2 gap-5">
        <Skeleton className="h-56" />
        <Skeleton className="h-56" />
      </div>
    </main>
  )
}
