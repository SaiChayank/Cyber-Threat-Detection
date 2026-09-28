import Link from 'next/link'
import { Brand } from '@/components/brand'
import { buttonClass } from '@/components/ui/button'
export default function NotFound() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-7 px-6 text-center">
      <Brand />
      <p className="text-sm tracking-widest text-lilac">404 / SIGNAL LOST</p>
      <h1 className="font-display text-4xl">This page is out of range.</h1>
      <p className="text-muted">Return to the platform or open the threat monitor.</p>
      <Link className={buttonClass('primary')} href="/monitor">
        Open monitor
      </Link>
      <Link className="text-sm text-muted hover:text-white" href="/">
        Back to platform
      </Link>
    </main>
  )
}
