'use client'
import { useEffect, useRef, useState } from 'react'
import { Pause, Play, ShieldCheck } from 'lucide-react'
import { cn } from '@/lib/utils'

export function SceneView({
  mode,
  className,
  controls = false,
}: {
  mode: 'pipeline' | 'agents'
  className?: string
  controls?: boolean
}) {
  const container = useRef<HTMLDivElement>(null)
  const scene = useRef<ReturnType<typeof import('@/scene').mountScene> | null>(null)
  const [status, setStatus] = useState<'loading' | 'ready' | 'fallback'>('loading')
  const [paused, setPaused] = useState(false)
  useEffect(() => {
    let disposed = false
    const node = container.current
    if (!node) return
    const stateObserver = new MutationObserver(() => {
      if (!disposed && node.dataset.render)
        setStatus(node.dataset.render === 'fallback' ? 'fallback' : 'ready')
    })
    stateObserver.observe(node, { attributes: true, attributeFilter: ['data-render'] })
    const visibility = new IntersectionObserver(
      (entries) => {
        if (!entries.some((entry) => entry.isIntersecting)) return
        visibility.disconnect()
        import('@/scene')
          .then(({ mountScene }) => {
            if (disposed) return
            try {
              scene.current = mountScene(node, mode)
              setStatus(node.dataset.render === 'fallback' ? 'fallback' : 'ready')
            } catch {
              setStatus('fallback')
            }
          })
          .catch(() => {
            if (!disposed) setStatus('fallback')
          })
      },
      { rootMargin: '200px' },
    )
    visibility.observe(node)
    return () => {
      disposed = true
      visibility.disconnect()
      stateObserver.disconnect()
      scene.current?.dispose()
      scene.current = null
    }
  }, [mode])
  return (
    <div className={cn('relative', className)}>
      <div
        ref={container}
        role="img"
        aria-label={
          mode === 'pipeline'
            ? 'Illustration: captured signals pass through a purple analysis portal in one direction'
            : 'Three metallic observation robots with purple sensor eyes'
        }
        className="scene-surface absolute inset-0"
      />
      {status === 'loading' && (
        <div className="absolute inset-0 grid place-items-center text-xs text-muted" role="status">
          <span className="animate-pulse">Assembling the observation layer…</span>
        </div>
      )}
      {status === 'fallback' && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-4 text-muted">
          <ShieldCheck size={80} strokeWidth={0.8} className="text-lilac" />
          <span className="text-xs">Passive signals → analysis → evidence</span>
          <span className="text-[10px]">3D preview unavailable on this device</span>
        </div>
      )}
      {controls && (
        <div className="absolute right-1 bottom-3 left-1 flex items-center justify-between gap-2 text-[9px] tracking-[.12em] text-muted uppercase">
          <span>01 / Pipeline illustration</span>
          <button
            className="flex min-h-11 items-center gap-2 rounded-lg px-2 text-[10px] hover:text-white focus-visible:outline-2 focus-visible:outline-lilac"
            aria-label={paused ? 'Play animation' : 'Pause animation'}
            aria-pressed={paused}
            disabled={status !== 'ready'}
            onClick={() => {
              const next = !paused
              setPaused(next)
              scene.current?.setPaused(next)
            }}
          >
            {paused ? <Play size={12} /> : <Pause size={12} />}{' '}
            {paused ? 'Play motion' : 'Pause motion'}
          </button>
        </div>
      )}
    </div>
  )
}
