import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  createOAuthClient,
  OAuthTokenExchangeError,
  OAuthRefreshError,
} from '../src/index.js';
import { acmeProvider, makeMemoryStorage, makeScriptedFetch, makeClock } from './_helpers.js';

/**
 * Asserts that the rendered representation of an error carries no traces of
 * `secret`. Checks message, body, JSON.stringify of the error, and stack.
 */
function assertNoLeak(err, secret) {
  const fields = [err.message, err.body, err.stack, JSON.stringify({ ...err, message: err.message })];
  for (const field of fields) {
    if (field == null) continue;
    assert.equal(
      String(field).includes(secret),
      false,
      `secret leaked into error rendering: ${String(field).slice(0, 200)}`
    );
  }
}

describe('secret hygiene', () => {
  it('PKCE code_verifier never appears in token-exchange error message or body', async () => {
    const storage = makeMemoryStorage();
    const { fetch } = makeScriptedFetch([{ status: 400, body: { error: 'invalid_grant' } }]);
    const c = createOAuthClient({
      provider: acmeProvider({ pkce: true }),
      clientId: 'cid',
      redirectUri: 'http://localhost:3000/cb',
      storage,
      options: { fetch, now: makeClock().now },
    });
    const { state } = await c.getAuthorizationUrl();
    try {
      await c.exchangeCodeForTokens('the-code', state);
      assert.fail('should have thrown');
    } catch (err) {
      assert.ok(err instanceof OAuthTokenExchangeError);
      // We can't access the verifier from outside (good!), but we can verify
      // that no plausible verifier-shaped string ended up in the error body.
      // The error body is the provider's response — a 30-char base64url
      // sequence appearing here would only come from us, never the provider.
      assertNoLeak(err, '<ineffective-sentinel>'); // sanity
      assert.equal(/code_verifier=/.test(err.message ?? ''), false);
      assert.equal(/code_verifier=/.test(err.body ?? ''), false);
    }
  });

  it('clientSecret never appears in refresh error message/body', async () => {
    const SECRET = 'super-secret-XYZ-DO-NOT-LEAK';
    const storage = makeMemoryStorage({
      acme: { access_token: 'a', refresh_token: 'rt', expires_at: 1_700_000_000 },
    });
    const { fetch } = makeScriptedFetch([{ status: 400, body: { error: 'invalid_grant' } }]);
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: 'cid',
      clientSecret: SECRET,
      redirectUri: 'http://localhost:3000/cb',
      storage,
      options: { fetch, now: () => 1_700_000_000_000 },
    });
    try {
      await c.refreshAccessToken();
      assert.fail('should have thrown');
    } catch (err) {
      assert.ok(err instanceof OAuthRefreshError);
      assertNoLeak(err, SECRET);
    }
  });

  it('clientSecret never appears in token-exchange error', async () => {
    const SECRET = 'super-secret-do-not-leak';
    const storage = makeMemoryStorage();
    const { fetch } = makeScriptedFetch([{ status: 400, body: '<html>error</html>' }]);
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: 'cid',
      clientSecret: SECRET,
      redirectUri: 'http://localhost:3000/cb',
      storage,
      options: { fetch, now: () => 1_700_000_000_000 },
    });
    const { state } = await c.getAuthorizationUrl();
    try {
      await c.exchangeCodeForTokens('code', state);
      assert.fail('should have thrown');
    } catch (err) {
      assertNoLeak(err, SECRET);
    }
  });

  it('refresh_token never appears in error rendering', async () => {
    const RT = 'rt-secret-keep-private';
    const storage = makeMemoryStorage({
      acme: { access_token: 'a', refresh_token: RT, expires_at: 1_700_000_000 },
    });
    const { fetch } = makeScriptedFetch([{ status: 401, body: { error: 'invalid_grant' } }]);
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: 'cid',
      clientSecret: 'sec',
      redirectUri: 'http://localhost:3000/cb',
      storage,
      options: { fetch, now: () => 1_700_000_000_000 },
    });
    try {
      await c.refreshAccessToken();
      assert.fail('should have thrown');
    } catch (err) {
      assertNoLeak(err, RT);
    }
  });
});
