'use client'
import { useEffect, useState } from 'react'
import { api } from '@/services/api'

export function useHealth() {
  const [status, setStatus] = useState<'connecting' | 'online' | 'offline'>('connecting')
  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout>
    async function check() {
      try {
        const health = await api.health(controller.signal)
        if (!controller.signal.aborted) setStatus(health.status === 'online' ? 'online' : 'offline')
      } catch {
        if (!controller.signal.aborted) setStatus('offline')
      }
      if (!controller.signal.aborted) timer = setTimeout(check, 15000)
    }
    void check()
    return () => {
      controller.abort()
      clearTimeout(timer)
    }
  }, [])
  return status
}
