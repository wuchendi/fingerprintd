// Aggregation barrel for the single edge database (libSQL or D1): the
// fingerprint state tables (`fingerprint.schema.ts`), the identify events
// (`events.schema.ts`) and the check-in event log (`checkin.schema.ts`). The
// Drizzle client (`client.ts`) imports `* as schema` from here, so one `getDb`
// serves every domain.

export * from './checkin.schema'
export * from './events.schema'
export * from './fingerprint.schema'
