'use client'
import { useEffect } from 'react'
import { animate, motion, useMotionValue, useReducedMotion, useTransform } from 'motion/react'
import { formatNumber } from '@/lib/utils'
import { easeOut } from '@/lib/motion'

export function AnimatedNumber({
  value,
  decimals,
  className,
}: {
  value: number
  decimals?: number
  className?: string
}) {
  const reducedMotion = useReducedMotion()
  const current = useMotionValue(value)
  const format = (number: number) =>
    decimals === undefined ? formatNumber(Math.round(number)) : number.toFixed(decimals)
  const display = useTransform(current, format)
  useEffect(() => {
    if (reducedMotion) {
      current.set(value)
      return
    }
    const animation = animate(current, value, { duration: 0.5, ease: easeOut })
    return () => animation.stop()
  }, [current, reducedMotion, value])
  return (
    <span className={className}>
      <span className="sr-only">{format(value)}</span>
      <motion.span aria-hidden="true">{display}</motion.span>
    </span>
  )
}
