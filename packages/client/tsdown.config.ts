import { defineConfig } from 'tsdown'

// ESM library build with a bundled `.d.ts`. Browser SDK — no Node shims.
export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'es2022',
  platform: 'browser',
})
