/**
 * Unit tests for access-token expiry logic.
 * Unlike the older suites, these import the real implementation.
 */
import { describe, it, expect } from '@jest/globals';
import {
  getTokenExpiry,
  isTokenStale,
  TOKEN_REFRESH_BUFFER_MS
} from '../../lib/tokenExpiry.mjs';

/** Builds a JWT-shaped token whose `exp` claim is `secondsFromNow` out. */
function makeJwt(secondsFromNow) {
  const exp = Math.floor(Date.now() / 1000) + secondsFromNow;
  const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  return `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ exp })}.sig`;
}

describe('getTokenExpiry', () => {
  it('reads the exp claim from a JWT', () => {
    const expiry = getTokenExpiry(makeJwt(3600));
    expect(expiry).toBeGreaterThan(Date.now() + 3500 * 1000);
    expect(expiry).toBeLessThan(Date.now() + 3700 * 1000);
  });

  it('prefers the JWT exp claim over the metadata field', () => {
    const jwt = makeJwt(3600);
    const misleading = new Date(Date.now() - 86400000).toISOString();
    expect(getTokenExpiry(jwt, misleading)).toBeGreaterThan(Date.now());
  });

  it('falls back to metadata expiresOn for an opaque token', () => {
    const iso = new Date(Date.now() + 600000).toISOString();
    expect(getTokenExpiry('opaque-token-value', iso)).toBe(Date.parse(iso));
  });

  it('returns null when expiry cannot be determined', () => {
    expect(getTokenExpiry('opaque-token-value')).toBeNull();
    expect(getTokenExpiry('opaque-token-value', 'not-a-date')).toBeNull();
  });

  it('handles empty, null, and malformed tokens without throwing', () => {
    expect(getTokenExpiry('')).toBeNull();
    expect(getTokenExpiry(null)).toBeNull();
    expect(getTokenExpiry(undefined)).toBeNull();
    expect(getTokenExpiry('a.b.c')).toBeNull();
    expect(getTokenExpiry('....')).toBeNull();
  });

  it('returns null for a JWT whose payload has no numeric exp', () => {
    const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
    expect(getTokenExpiry(`${b64({})}.${b64({ sub: 'x' })}.sig`)).toBeNull();
    expect(getTokenExpiry(`${b64({})}.${b64({ exp: 'soon' })}.sig`)).toBeNull();
  });
});

describe('isTokenStale', () => {
  const now = 1_700_000_000_000;

  it('treats an expired token as stale', () => {
    expect(isTokenStale(now - 60_000, now)).toBe(true);
  });

  it('treats a token inside the refresh buffer as stale', () => {
    expect(isTokenStale(now + TOKEN_REFRESH_BUFFER_MS - 1000, now)).toBe(true);
  });

  it('treats a token beyond the refresh buffer as fresh', () => {
    expect(isTokenStale(now + TOKEN_REFRESH_BUFFER_MS + 1000, now)).toBe(false);
  });

  it('treats an unknown expiry as fresh so opaque tokens keep working', () => {
    expect(isTokenStale(null, now)).toBe(false);
  });

  it('uses a 10 minute buffer by default', () => {
    expect(TOKEN_REFRESH_BUFFER_MS).toBe(10 * 60 * 1000);
  });
});

describe('regression: expired token file must not be adopted', () => {
  // The original bug: loadExistingToken() adopted an expired token, which made
  // accessToken truthy, which made ensureGraphClient() skip silent renewal
  // entirely — so every tool call 401'd while a valid refresh token sat unused
  // in the Keychain.
  it('marks an hour-old token from disk as stale', () => {
    const staleToken = makeJwt(-3600);
    const expiry = getTokenExpiry(staleToken, new Date(Date.now() - 3600000).toISOString());
    expect(expiry).not.toBeNull();
    expect(isTokenStale(expiry)).toBe(true);
  });
});
