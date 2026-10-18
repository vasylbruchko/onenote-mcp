/**
 * Pure access-token expiry logic, kept in its own module so it can be unit
 * tested directly rather than reimplemented in the test file.
 */

// Treat a token as unusable once it is within this window of expiring, so a
// long-running request can't have its token die mid-flight.
export const TOKEN_REFRESH_BUFFER_MS = 10 * 60 * 1000; // 10 minutes

/**
 * Determines when an access token expires, in epoch milliseconds.
 * Prefers the JWT's own `exp` claim — it is authoritative and is the only
 * source available for legacy plain-text token files — and falls back to the
 * `expiresOn` metadata written alongside the token.
 * @param {string} token - The raw access token.
 * @param {string | null} [metadataExpiresOn] - ISO date from the token file, if any.
 * @returns {number | null} Epoch ms, or null if expiry cannot be determined.
 */
export function getTokenExpiry(token, metadataExpiresOn = null) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length === 3) {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      if (typeof payload.exp === 'number') {
        return payload.exp * 1000;
      }
    }
  } catch (error) {
    // Not a decodable JWT — fall through to the metadata field.
  }
  if (metadataExpiresOn) {
    const parsed = Date.parse(metadataExpiresOn);
    if (!Number.isNaN(parsed)) {
      return parsed;
    }
  }
  return null;
}

/**
 * Whether a token with the given expiry should be refreshed rather than used.
 * An unknown expiry (null) is treated as fresh, so opaque (non-JWT) tokens
 * keep working.
 * @param {number | null} expiresAt - Epoch ms, or null if unknown.
 * @param {number} [now] - Current time in epoch ms.
 * @param {number} [bufferMs] - Refresh buffer.
 * @returns {boolean}
 */
export function isTokenStale(expiresAt, now = Date.now(), bufferMs = TOKEN_REFRESH_BUFFER_MS) {
  if (expiresAt === null) return false;
  return expiresAt - now <= bufferMs;
}
