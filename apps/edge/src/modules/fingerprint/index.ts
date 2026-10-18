/**
 * Fingerprint module barrel — the domain's public surface: the scoring engine,
 * the candidate store, and the Hono sub-router. Consumers (the composition
 * root in `index.ts`, `app.ts`, tests) import from here rather than reaching into
 * the module's files.
 */

export { EdgeEngine, initEngineRuntime } from './engine'
export type { FingerprintDeps } from './fingerprint.routes'
export { fingerprintRoutes } from './fingerprint.routes'
export { DEFAULT_MAX_BLOCK, FingerprintStore } from './fingerprint-store'
