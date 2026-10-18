/**
 * Bearer-credential check shared by the key-gated endpoints: erasure
 * (`FP_ADMIN_KEY`), the events API and check-in (`FP_API_KEY`).
 */

/** Whether `header` is `Bearer <key>`, compared in constant time. */
export function bearerAuthorized(
  header: string | undefined,
  key: string,
): boolean {
  const token = bearerToken(header)
  return token !== undefined && constantTimeEqual(token, key)
}

/** Extract the token from an `Authorization: Bearer <token>` header, or
 *  `undefined` when the header is absent or not a bearer credential. */
function bearerToken(header: string | undefined): string | undefined {
  if (header === undefined) return undefined
  const match = /^Bearer (.+)$/.exec(header)
  return match ? match[1] : undefined
}

/**
 * Constant-time string equality for the credential check: unequal lengths
 * fail fast, but equal-length inputs are compared by XOR-accumulating every
 * char code so the loop never short-circuits on the first mismatch — a timing
 * side channel must not leak how many leading characters matched.
 */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }
  return diff === 0
}
