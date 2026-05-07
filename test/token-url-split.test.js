import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { createOAuthClient, OAuthConfigError } from '../src/index.js';
import { acmeProvider, makeMemoryStorage, makeScriptedFetch, makeClock } from './_helpers.js';

describe('provider.tokenUrl object-form (split endpoints)', () => {
  it('uses tokenUrl.exchange for code exchange', async () => {
    const clock = makeClock(1_700_000_000);
    const storage = makeMemoryStorage();
    const { fetch, calls } = makeScriptedFetch([
      { status: 200, body: { access_token: 'at', refresh_token: 'rt', expires_in: 3600 } },
    ]);
    const c = createOAuthClient({
      provider: acmeProvider({
        tokenUrl: {
          exchange: 'https://auth.example/oauth/exchange',
          refresh: 'https://auth.example/oauth/refresh',
        },
      }),
      clientId: 'cid',
      clientSecret: 'sec',
      redirectUri: 'http://localhost:3000/cb',
      storage,
      options: { fetch, now: clock.now },
    });
    const { state } = await c.getAuthorizationUrl();
    await c.exchangeCodeForTokens('code', state);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'https://auth.example/oauth/exchange');
  });

  it('uses tokenUrl.refresh for refresh grant', async () => {
    const storage = makeMemoryStorage({
      acme: { access_token: 'old', refresh_token: 'rt', expires_at: 1_700_000_000 },
    });
    const { fetch, calls } = makeScriptedFetch([
      { status: 200, body: { access_token: 'fresh', expires_in: 3600 } },
    ]);
    const c = createOAuthClient({
      provider: acmeProvider({
        tokenUrl: {
          exchange: 'https://auth.example/oauth/exchange',
          refresh: 'https://auth.example/oauth/refresh',
        },
      }),
      clientId: 'cid',
      clientSecret: 'sec',
      redirectUri: 'http://localhost:3000/cb',
      storage,
      options: { fetch, now: () => 1_700_000_000_000 },
    });
    await c.refreshAccessToken();
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'https://auth.example/oauth/refresh');
  });

  it('hits both URLs across full lifecycle', async () => {
    const clock = makeClock(1_700_000_000);
    const storage = makeMemoryStorage();
    const { fetch, calls } = makeScriptedFetch([
      { status: 200, body: { access_token: 'at', refresh_token: 'rt', expires_in: 3600 } },
      { status: 200, body: { access_token: 'fresh', expires_in: 3600 } },
    ]);
    const c = createOAuthClient({
      provider: acmeProvider({
        tokenUrl: {
          exchange: 'https://auth.example/oauth/exchange',
          refresh: 'https://auth.example/oauth/refresh',
        },
      }),
      clientId: 'cid',
      clientSecret: 'sec',
      redirectUri: 'http://localhost:3000/cb',
      storage,
      options: { fetch, now: clock.now },
    });
    const { state } = await c.getAuthorizationUrl();
    await c.exchangeCodeForTokens('code', state);
    await c.refreshAccessToken();
    assert.equal(calls.length, 2);
    assert.equal(calls[0].url, 'https://auth.example/oauth/exchange');
    assert.equal(calls[1].url, 'https://auth.example/oauth/refresh');
  });

  it('throws OAuthConfigError when object missing exchange', () => {
    assert.throws(
      () =>
        createOAuthClient({
          provider: acmeProvider({ tokenUrl: { refresh: 'https://auth.example/refresh' } }),
          clientId: 'cid',
          redirectUri: 'http://localhost:3000/cb',
          storage: makeMemoryStorage(),
        }),
      OAuthConfigError
    );
  });

  it('throws OAuthConfigError when object missing refresh', () => {
    assert.throws(
      () =>
        createOAuthClient({
          provider: acmeProvider({ tokenUrl: { exchange: 'https://auth.example/exchange' } }),
          clientId: 'cid',
          redirectUri: 'http://localhost:3000/cb',
          storage: makeMemoryStorage(),
        }),
      OAuthConfigError
    );
  });

  it('throws OAuthConfigError when exchange URL is invalid', () => {
    assert.throws(
      () =>
        createOAuthClient({
          provider: acmeProvider({
            tokenUrl: { exchange: 'not-a-url', refresh: 'https://auth.example/refresh' },
          }),
          clientId: 'cid',
          redirectUri: 'http://localhost:3000/cb',
          storage: makeMemoryStorage(),
        }),
      OAuthConfigError
    );
  });

  it('throws OAuthConfigError when refresh URL is invalid', () => {
    assert.throws(
      () =>
        createOAuthClient({
          provider: acmeProvider({
            tokenUrl: { exchange: 'https://auth.example/exchange', refresh: '://broken' },
          }),
          clientId: 'cid',
          redirectUri: 'http://localhost:3000/cb',
          storage: makeMemoryStorage(),
        }),
      OAuthConfigError
    );
  });

  it('throws OAuthConfigError when tokenUrl is non-string non-object (number)', () => {
    assert.throws(
      () =>
        createOAuthClient({
          provider: acmeProvider({ tokenUrl: 42 }),
          clientId: 'cid',
          redirectUri: 'http://localhost:3000/cb',
          storage: makeMemoryStorage(),
        }),
      OAuthConfigError
    );
  });

  it('string-form still works (backwards compatibility)', async () => {
    const clock = makeClock(1_700_000_000);
    const storage = makeMemoryStorage();
    const { fetch, calls } = makeScriptedFetch([
      { status: 200, body: { access_token: 'at', refresh_token: 'rt', expires_in: 3600 } },
      { status: 200, body: { access_token: 'fresh', expires_in: 3600 } },
    ]);
    // Plain string — same URL used for both endpoints (the common case)
    const c = createOAuthClient({
      provider: acmeProvider({ tokenUrl: 'https://auth.example/oauth/token' }),
      clientId: 'cid',
      clientSecret: 'sec',
      redirectUri: 'http://localhost:3000/cb',
      storage,
      options: { fetch, now: clock.now },
    });
    const { state } = await c.getAuthorizationUrl();
    await c.exchangeCodeForTokens('code', state);
    await c.refreshAccessToken();
    assert.equal(calls[0].url, 'https://auth.example/oauth/token');
    assert.equal(calls[1].url, 'https://auth.example/oauth/token');
  });
});
