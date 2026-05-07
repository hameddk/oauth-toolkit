import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  createOAuthClient,
  OAuthStateError,
  OAuthTokenExchangeError,
  OAuthError,
} from '../src/index.js';
import { acmeProvider, makeMemoryStorage, makeScriptedFetch, makeClock } from './_helpers.js';

function makeClient({ provider = {}, fetchScript = [], clock = makeClock(), ...rest } = {}) {
  const storage = makeMemoryStorage();
  const { fetch, calls } = makeScriptedFetch(fetchScript);
  const c = createOAuthClient({
    provider: acmeProvider(provider),
    clientId: 'cid',
    clientSecret: 'sec',
    redirectUri: 'http://localhost:3000/cb',
    storage,
    options: { fetch, now: clock.now },
    ...rest,
  });
  return { client: c, storage, fetch, calls, clock };
}

describe('exchangeCodeForTokens', () => {
  it('saves tokens (body+form, default flow)', async () => {
    const { client, storage, calls, clock } = makeClient({
      fetchScript: [{ status: 200, body: { access_token: 'at', refresh_token: 'rt', expires_in: 3600 } }],
    });
    const { state } = await client.getAuthorizationUrl();
    const result = await client.exchangeCodeForTokens('code-xyz', state);

    assert.equal(result.access_token, 'at');
    assert.equal(result.expires_at, clock.nowSec() + 3600);
    assert.deepEqual(result.raw, { access_token: 'at', refresh_token: 'rt', expires_in: 3600 });

    const stored = storage._peek('acme');
    assert.equal(stored.access_token, 'at');
    assert.equal(stored.refresh_token, 'rt');
    assert.equal(stored.expires_at, clock.nowSec() + 3600);

    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'https://auth.acme.example/oauth/token');
    assert.equal(calls[0].options.method, 'POST');
    assert.equal(calls[0].options.headers['Content-Type'], 'application/x-www-form-urlencoded');
    const body = new URLSearchParams(calls[0].options.body);
    assert.equal(body.get('grant_type'), 'authorization_code');
    assert.equal(body.get('code'), 'code-xyz');
    assert.equal(body.get('client_id'), 'cid');
    assert.equal(body.get('client_secret'), 'sec');
  });

  it('uses Basic auth when tokenEndpointAuth: "basic"', async () => {
    const { client, calls } = makeClient({
      provider: { tokenEndpointAuth: 'basic' },
      fetchScript: [{ status: 200, body: { access_token: 'at', refresh_token: 'rt', expires_in: 3600 } }],
    });
    const { state } = await client.getAuthorizationUrl();
    await client.exchangeCodeForTokens('c', state);

    const auth = calls[0].options.headers.Authorization;
    assert.match(auth, /^Basic /);
    const decoded = Buffer.from(auth.replace('Basic ', ''), 'base64').toString('utf8');
    assert.equal(decoded, 'cid:sec');
    const body = new URLSearchParams(calls[0].options.body);
    assert.equal(body.get('client_secret'), null, 'secret must NOT be in body when using basic auth');
    assert.equal(body.get('client_id'), null, 'client_id stays in header when using basic auth');
  });

  it('uses JSON body when tokenEndpointFormat: "json"', async () => {
    const { client, calls } = makeClient({
      provider: { tokenEndpointFormat: 'json' },
      fetchScript: [{ status: 200, body: { access_token: 'at', refresh_token: 'rt', expires_in: 3600 } }],
    });
    const { state } = await client.getAuthorizationUrl();
    await client.exchangeCodeForTokens('c', state);
    assert.equal(calls[0].options.headers['Content-Type'], 'application/json');
    const json = JSON.parse(calls[0].options.body);
    assert.equal(json.grant_type, 'authorization_code');
    assert.equal(json.client_id, 'cid');
    assert.equal(json.client_secret, 'sec');
  });

  it('sends code_verifier when PKCE enabled', async () => {
    const { client, calls } = makeClient({
      provider: { pkce: true },
      fetchScript: [{ status: 200, body: { access_token: 'at', refresh_token: 'rt', expires_in: 3600 } }],
    });
    const { state } = await client.getAuthorizationUrl();
    await client.exchangeCodeForTokens('c', state);
    const body = new URLSearchParams(calls[0].options.body);
    assert.match(body.get('code_verifier'), /^[A-Za-z0-9_-]+$/);
  });

  it('throws OAuthStateError on unknown state', async () => {
    const { client } = makeClient({ fetchScript: [] });
    await assert.rejects(
      () => client.exchangeCodeForTokens('c', 'never-issued-state'),
      OAuthStateError
    );
  });

  it('throws OAuthError on missing code', async () => {
    const { client } = makeClient();
    await assert.rejects(() => client.exchangeCodeForTokens('', 'st'), OAuthError);
  });

  it('throws OAuthTokenExchangeError on provider 400 with body', async () => {
    const { client } = makeClient({
      fetchScript: [{ status: 400, body: { error: 'invalid_grant' } }],
    });
    const { state } = await client.getAuthorizationUrl();
    try {
      await client.exchangeCodeForTokens('c', state);
      assert.fail('should have thrown');
    } catch (err) {
      assert.ok(err instanceof OAuthTokenExchangeError);
      assert.equal(err.status, 400);
      assert.match(err.body, /invalid_grant/);
    }
  });

  it('throws OAuthTokenExchangeError on non-JSON response', async () => {
    const { client } = makeClient({
      fetchScript: [{ status: 200, body: '<html>oops</html>' }],
    });
    const { state } = await client.getAuthorizationUrl();
    await assert.rejects(() => client.exchangeCodeForTokens('c', state), OAuthTokenExchangeError);
  });

  it('throws OAuthTokenExchangeError when access_token missing', async () => {
    const { client } = makeClient({
      fetchScript: [{ status: 200, body: { not_a_token: 'oops' } }],
    });
    const { state } = await client.getAuthorizationUrl();
    await assert.rejects(() => client.exchangeCodeForTokens('c', state), OAuthTokenExchangeError);
  });

  it('uses custom parseTokenResponse for nested provider response', async () => {
    // Slack-style: actual token nested under authed_user
    const { client, storage } = makeClient({
      provider: {
        parseTokenResponse: (data) => ({
          access_token: data.authed_user?.access_token,
          refresh_token: data.authed_user?.refresh_token,
          expires_in: data.authed_user?.expires_in,
        }),
      },
      fetchScript: [
        {
          status: 200,
          body: {
            ok: true,
            authed_user: { access_token: 'xoxp-abc', refresh_token: 'xrt', expires_in: 43200 },
          },
        },
      ],
    });
    const { state } = await client.getAuthorizationUrl();
    const result = await client.exchangeCodeForTokens('c', state);
    assert.equal(result.access_token, 'xoxp-abc');
    assert.equal(storage._peek('acme').refresh_token, 'xrt');
  });

  it('clears state after successful exchange (state cannot be reused)', async () => {
    const { client } = makeClient({
      fetchScript: [
        { status: 200, body: { access_token: 'at', refresh_token: 'rt', expires_in: 3600 } },
      ],
    });
    const { state } = await client.getAuthorizationUrl();
    await client.exchangeCodeForTokens('c', state);
    await assert.rejects(() => client.exchangeCodeForTokens('c', state), OAuthStateError);
  });

  it('clears state even after failed exchange (single-use)', async () => {
    const { client } = makeClient({
      fetchScript: [{ status: 400, body: { error: 'invalid_grant' } }],
    });
    const { state } = await client.getAuthorizationUrl();
    await assert.rejects(() => client.exchangeCodeForTokens('c', state), OAuthTokenExchangeError);
    // Note: by spec, state IS cleared even on token-exchange failure (it's been used).
    // Re-attempting must restart the flow.
    await assert.rejects(() => client.exchangeCodeForTokens('c', state), OAuthStateError);
  });

  it('uses defaultExpiresInSec when provider omits expires_in', async () => {
    const { client, clock } = makeClient({
      fetchScript: [{ status: 200, body: { access_token: 'at', refresh_token: 'rt' } }],
    });
    const { state } = await client.getAuthorizationUrl();
    const result = await client.exchangeCodeForTokens('c', state);
    assert.equal(result.expires_at, clock.nowSec() + 3600);
  });
});

describe('exchangeCodeForTokens — state TTL', () => {
  it('rejects state after TTL expires', async () => {
    const clock = makeClock(1_700_000_000);
    const { client } = makeClient({
      clock,
      fetchScript: [],
      // override stateTtlMs to 60s for this test
      // (passed via options below)
    });
    // Re-create with 60s TTL to keep test isolated
    const storage = makeMemoryStorage();
    const { fetch } = makeScriptedFetch([]);
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: 'cid',
      clientSecret: 'sec',
      redirectUri: 'http://localhost:3000/cb',
      storage,
      options: { fetch, now: clock.now, stateTtlMs: 60_000 },
    });
    const { state } = await c.getAuthorizationUrl();
    clock.advanceSec(120); // > 60s TTL
    await assert.rejects(() => c.exchangeCodeForTokens('code', state), OAuthStateError);
  });

  it('keeps state valid while inside TTL window', async () => {
    const clock = makeClock(1_700_000_000);
    const storage = makeMemoryStorage();
    const { fetch } = makeScriptedFetch([
      { status: 200, body: { access_token: 'at', refresh_token: 'rt', expires_in: 3600 } },
    ]);
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: 'cid',
      clientSecret: 'sec',
      redirectUri: 'http://localhost:3000/cb',
      storage,
      options: { fetch, now: clock.now, stateTtlMs: 60_000 },
    });
    const { state } = await c.getAuthorizationUrl();
    clock.advanceSec(30);
    const result = await c.exchangeCodeForTokens('code', state);
    assert.equal(result.access_token, 'at');
  });
});
