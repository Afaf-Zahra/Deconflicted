import { cpSync, existsSync, readFileSync } from 'node:fs'
import { resolve, sep } from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import type { Plugin } from 'vite'
import { defineConfig } from 'vitest/config'

const API = 'http://localhost:8000'
// Paths the screens call. The dev server forwards them to the API, so the same URLs work in dev and in Docker.
// docker/nginx.conf forwards the same list; a test keeps the two in step.
const API_PATHS = ['/incidents', '/budget', '/events', '/response', '/ledger', '/audit', '/decoys', '/debug', '/ingest', '/health']

/** The .json file inside dir that a request path names, or null. It never leaves dir. */
export function mockFile(dir: string, urlPath: string): string | null {
  let name: string
  try {
    name = decodeURIComponent(urlPath.split('?')[0]).replace(/^\/+/, '')
  } catch {
    return null
  }
  const file = resolve(dir, name)
  if (!name.endsWith('.json') || !file.startsWith(dir + sep) || !existsSync(file)) return null
  return file
}

/** Serves web/mock at /mock in dev. A build copies it into dist, unless the build talks to the live API. */
export function mockFiles(): Plugin {
  let mockDir = ''
  let outDir = ''
  let building = false
  return {
    name: 'deconflicted-mock-files',
    configResolved(config) {
      mockDir = resolve(config.root, 'mock')
      outDir = resolve(config.root, config.build.outDir)
      building = config.command === 'build'
    },
    configureServer(server) {
      server.middlewares.use('/mock', (req, res, next) => {
        const file = mockFile(mockDir, req.url ?? '')
        if (!file) return next()
        res.setHeader('Content-Type', 'application/json')
        res.end(readFileSync(file))
      })
    },
    closeBundle() {
      if (!building || process.env.VITE_API === 'live' || !existsSync(mockDir)) return
      cpSync(mockDir, resolve(outDir, 'mock'), { recursive: true })
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss(), mockFiles()],
  server: {
    proxy: {
      // Local FastAPI backend. Fully offline: no external hosts.
      '/api': { target: API, changeOrigin: true, rewrite: (path) => path.replace(/^\/api/, '') },
      ...Object.fromEntries(API_PATHS.map((path) => [path, { target: API, changeOrigin: true }])),
    },
  },
  test: {
    environment: 'jsdom',
    include: ['tests/**/*.test.{ts,tsx}'],
    setupFiles: ['./tests/setup.ts'],
    css: false,
  },
})