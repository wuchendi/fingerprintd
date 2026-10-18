/**
 * Events module barrel — the domain's public surface: the identify event store
 * and the `GET /events/:request_id` sub-router. Consumers (the composition
 * root in `index.ts`, `app.ts`, tests) import from here rather than reaching
 * into the module's files.
 */

export type { EventsDeps } from './events.routes'
export { eventsRoutes } from './events.routes'
export { EventStore } from './events-store'
