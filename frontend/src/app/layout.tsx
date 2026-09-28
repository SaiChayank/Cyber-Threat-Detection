import type { Metadata } from 'next'
import localFont from 'next/font/local'
import { Providers } from '@/components/providers'
import './globals.css'

const display = localFont({
  src: [
    { path: '../assets/fonts/space-grotesk-regular.woff2', weight: '400' },
    { path: '../assets/fonts/space-grotesk-medium.woff2', weight: '500' },
    { path: '../assets/fonts/space-grotesk-bold.woff2', weight: '700' },
  ],
  variable: '--font-space-grotesk',
  display: 'swap',
})
const body = localFont({
  src: [
    { path: '../assets/fonts/dm-sans-regular.woff2', weight: '400' },
    { path: '../assets/fonts/dm-sans-medium.woff2', weight: '500' },
    { path: '../assets/fonts/dm-sans-bold.woff2', weight: '700' },
  ],
  variable: '--font-dm-sans',
  display: 'swap',
})

export const metadata: Metadata = {
  title: 'Sentinel · Passive threat intelligence',
  description:
    'One-way network observation, streaming threat detection and evidence-backed alerts. PS26145 research prototype for passive IP traffic analysis.',
  icons: { icon: '/assets/sentinel.svg' },
}
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      data-scroll-behavior="smooth"
      className={`${display.variable} ${body.variable}`}
    >
      <body className="font-sans antialiased">
        <a
          href="#main-content"
          className="sr-only z-100 focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:rounded-lg focus:bg-lime focus:px-4 focus:py-3 focus:text-ink"
        >
          Skip to content
        </a>
        <Providers>{children}</Providers>
      </body>
    </html>
  )
}
