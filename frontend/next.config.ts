import type { NextConfig } from 'next'

const api = (process.env.API_PROXY_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')
const config: NextConfig = {
  devIndicators: false,
  // EventSource needs each event flushed immediately, including small batches.
  compress: false,
  experimental: { proxyClientMaxBodySize: '20mb' },
  async rewrites() {
    return [
      { source: '/api/:path*', destination: `${api}/api/:path*` },
      { source: '/docs', destination: `${api}/docs` },
      { source: '/openapi.json', destination: `${api}/openapi.json` },
    ]
  },
}
export default config
