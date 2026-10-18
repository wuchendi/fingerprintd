import { configDefaults, defineConfig } from 'vitest/config'

// The router is state-free and dependency-injected, so it runs under plain Node
// with the WASM engine loaded from the vendored bytes — no Workers runtime
// needed for the unit contract. The database stores run here too, on libSQL,
// behind a guard that enforces D1's 100 bound-parameter cap
// (`tests/d1-param-guard.ts`). The Durable Objects and the D1 end-to-end path
// need real workerd, so those `*.workers.test.ts` files run in the sibling
// Workers project (`vitest.workers.config.ts`) and are excluded here.
export default defineConfig({
  test: {
    name: 'node',
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'tests/**/*.workers.test.ts'],
    setupFiles: ['./tests/d1-param-guard.ts'],
  },
})
