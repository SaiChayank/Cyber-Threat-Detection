'use client'
import { useEffect } from 'react'
import { Button } from '@/components/ui/button'
export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    console.error(error)
  }, [error])
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-5 px-6 text-center">
      <h1 className="font-display text-3xl">The interface needs a moment.</h1>
      <p className="max-w-md text-muted">
        A display error interrupted this page. Your recorded alerts remain in the local database.
      </p>
      <Button variant="primary" onClick={reset}>
        Try again
      </Button>
      <a href="/" className="text-sm text-lilac">
        Return home
      </a>
    </main>
  )
}
