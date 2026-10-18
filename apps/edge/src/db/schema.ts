// Aggregation barrel for the single edge database (libSQL or D1): both the
// fingerprint state tables (`fingerprint.schema.ts`) and the check-in event log
// (`checkin.schema.ts`). The Drizzle client (`client.ts`) imports `* as schema`
// from here, so one `getDb` serves both domains.

export * from './checkin.schema'
export * from './fingerprint.schema'
