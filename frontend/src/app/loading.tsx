import { Skeleton } from '@/components/ui/panel'
export default function Loading() {
  return (
    <main className="mx-auto max-w-7xl space-y-8 px-6 py-16" aria-label="Loading interface">
      <Skeleton className="h-10 w-52" />
      <Skeleton className="h-48 w-full" />
      <div className="grid grid-cols-2 gap-5">
        <Skeleton className="h-56" />
        <Skeleton className="h-56" />
      </div>
    </main>
  )
}
