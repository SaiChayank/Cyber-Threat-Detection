import { SiteNav } from '@/components/site-nav'
import { SiteFooter } from '@/components/site-footer'
import { Hero } from './hero'
import { Platform } from './platform'
import { Architecture, Detection } from './detection'

export function Landing() {
  return (
    <div className="relative isolate">
      <div className="product-background -z-10" aria-hidden="true" />
      <SiteNav />
      <main id="main-content">
        <Hero />
        <Platform />
        <Detection />
        <Architecture />
      </main>
      <SiteFooter />
    </div>
  )
}
