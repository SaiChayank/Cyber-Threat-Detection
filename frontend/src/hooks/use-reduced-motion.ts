'use client'
import { useSyncExternalStore } from 'react'

const preference = '(prefers-reduced-motion: reduce)'

function subscribe(onChange: () => void) {
  const query = window.matchMedia(preference)
  query.addEventListener('change', onChange)
  return () => query.removeEventListener('change', onChange)
}

function snapshot() {
  return window.matchMedia(preference).matches
}

// Keep hydration consistent; reflect browser preference changes without a reload.
export function useReducedMotion() {
  return useSyncExternalStore(subscribe, snapshot, () => false)
}
