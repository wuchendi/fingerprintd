/**
 * HTTP helpers shared by the route modules.
 */

import type { MiddlewareHandler } from 'hono'

/** `415` unless the body is declared JSON (`application/json` or a `+json`
 *  type), like the native extractor. */
export const requireJson: MiddlewareHandler = async (c, next) => {
  const mime = c.req.header('content-type')?.split(';')[0]?.trim().toLowerCase()
  const isJson =
    mime !== undefined &&
    (mime === 'application/json' ||
      (mime.startsWith('application/') && mime.endsWith('+json')))
  if (!isJson) return new Response(null, { status: 415 })
  await next()
}

/** A `200 application/json` response over an already-serialized body. */
export function jsonResponse(body: string): Response {
  return new Response(body, {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}
