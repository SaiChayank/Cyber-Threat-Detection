import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
const numberFormatter = new Intl.NumberFormat('en-US')
export const formatNumber = (value: number) => numberFormatter.format(value)
export const formatTime = (timestamp: number) => new Date(timestamp).toISOString().slice(11, 19)
export function evidenceValue(value: unknown) {
  if (typeof value === 'number') return Number(value.toFixed(4)).toString()
  if (value === null) return 'Unavailable'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}
