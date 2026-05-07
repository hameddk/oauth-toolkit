import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { createOAuthClient, OAuthConfigError } from '../src/index.js';
import { acmeProvider, makeMemoryStorage, makeScriptedFetch, makeClock } from './_helpers.js';

describe('lazy clientId / clientSecret resolvers', () => {
  it('accepts sync function for clientId', async () => {
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: () => 'sync-cid',
      redirectUri: 'http://localhost:3000/cb',
      storage: makeMemoryStorage(),
    });
    const { url } = await c.getAuthorizationUrl();
    const params = new URL(url).searchParams;
    assert.equal(params.get('client_id'), 'sync-cid');
  });

  it('accepts async function for clientId', async () => {
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: async () => 'async-cid',
      redirectUri: 'http://localhost:3000/cb',
      storage: makeMemoryStorage(),
    });
    const { url } = await c.getAuthorizationUrl();
    assert.equal(new URL(url).searchParams.get('client_id'), 'async-cid');
  });

  it('wraps thrown resolver error in OAuthConfigError with cause', async () => {
    const cause = new Error('vault unavailable');
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: () => {
        throw cause;
      },
      redirectUri: 'http://localhost:3000/cb',
      storage: makeMemoryStorage(),
    });
    try {
      await c.getAuthorizationUrl();
      assert.fail('should have thrown');
    } catch (err) {
      assert.ok(err instanceof OAuthConfigError);
      assert.equal(err.cause, cause);
      assert.match(err.message, /vault unavailable/);
    }
  });

  it('wraps async resolver rejection in OAuthConfigError', async () => {
    const cause = new Error('async fail');
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: async () => {
        throw cause;
      },
      redirectUri: 'http://localhost:3000/cb',
      storage: makeMemoryStorage(),
    });
    try {
      await c.getAuthorizationUrl();
      assert.fail('should have thrown');
    } catch (err) {
      assert.ok(err instanceof OAuthConfigError);
      assert.equal(err.cause, cause);
    }
  });

  it('throws OAuthConfigError when resolver returns empty string', async () => {
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: () => '',
      redirectUri: 'http://localhost:3000/cb',
      storage: makeMemoryStorage(),
    });
    await assert.rejects(() => c.getAuthorizationUrl(), OAuthConfigError);
  });

  it('calls clientId resolver every time (no internal caching)', async () => {
    let calls = 0;
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: () => {
        calls++;
        return `cid-${calls}`;
      },
      redirectUri: 'http://localhost:3000/cb',
      storage: makeMemoryStorage(),
    });
    const a = await c.getAuthorizationUrl();
    const b = await c.getAuthorizationUrl();
    assert.equal(new URL(a.url).searchParams.get('client_id'), 'cid-1');
    assert.equal(new URL(b.url).searchParams.get('client_id'), 'cid-2');
    assert.ok(calls >= 2);
  });

  it('calls clientSecret resolver on every token-endpoint hit', async () => {
    let secretCalls = 0;
    const clock = makeClock(1_700_000_000);
    const storage = makeMemoryStorage();
    const { fetch } = makeScriptedFetch([
      { status: 200, body: { access_token: 'a1', refresh_token: 'rt', expires_in: 3600 } },
      { status: 200, body: { access_token: 'a2', expires_in: 3600 } },
    ]);
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: 'cid',
      clientSecret: () => {
        secretCalls++;
        return 'sec';
      },
      redirectUri: 'http://localhost:3000/cb',
      storage,
      options: { fetch, now: clock.now },
    });
    const { state } = await c.getAuthorizationUrl();
    await c.exchangeCodeForTokens('code', state);
    await c.refreshAccessToken();
    assert.equal(secretCalls, 2, 'resolver called for exchange + refresh');
  });
});
