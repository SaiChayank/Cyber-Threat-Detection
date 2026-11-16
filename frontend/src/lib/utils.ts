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
const byteUnits = ['B', 'kB', 'MB', 'GB', 'TB']
function formatBytes(value: number) {
  let scaled = Math.abs(value)
  let unit = 0
  while (scaled >= 1000 && unit < byteUnits.length - 1) {
    scaled /= 1000
    unit += 1
  }
  const digits = unit === 0 ? 0 : scaled < 10 ? 2 : scaled < 100 ? 1 : 0
  return `${value < 0 ? '-' : ''}${scaled.toFixed(digits)} ${byteUnits[unit]}`
}
// Evidence keys name their unit; byte counts and byte rates read better in decimal units.
export function evidenceMetric(key: string, value: unknown) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return evidenceValue(value)
  if (/byte_rate/.test(key)) return `${formatBytes(value)}/s`
  if (/bytes?$|_bytes_/.test(key) && !/ratio|resolution/.test(key)) return formatBytes(value)
  if (Math.abs(value) >= 10000) return formatNumber(Number(value.toFixed(2)))
  return evidenceValue(value)
}
