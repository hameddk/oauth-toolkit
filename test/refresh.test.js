import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { createOAuthClient, OAuthRefreshError } from '../src/index.js';
import { acmeProvider, makeMemoryStorage, makeScriptedFetch, makeClock } from './_helpers.js';

function setup({ provider = {}, fetchScript = [], clock = makeClock(), initialTokens } = {}) {
  const storage = makeMemoryStorage(initialTokens ? { acme: initialTokens } : {});
  const { fetch, calls } = makeScriptedFetch(fetchScript);
  const c = createOAuthClient({
    provider: acmeProvider(provider),
    clientId: 'cid',
    clientSecret: 'sec',
    redirectUri: 'http://localhost:3000/cb',
    storage,
    options: { fetch, now: clock.now },
  });
  return { client: c, storage, fetch, calls, clock };
}

describe('refreshAccessToken', () => {
  it('happy path — saves new access_token', async () => {
    const clock = makeClock(1_700_000_000);
    const { client, storage } = setup({
      clock,
      initialTokens: { access_token: 'old-at', refresh_token: 'rt-1', expires_at: 1_700_000_000 },
      fetchScript: [{ status: 200, body: { access_token: 'new-at', expires_in: 3600 } }],
    });
    const tok = await client.refreshAccessToken();
    assert.equal(tok, 'new-at');
    const stored = storage._peek('acme');
    assert.equal(stored.access_token, 'new-at');
    assert.equal(stored.expires_at, clock.nowSec() + 3600);
  });

  it('preserves refresh_token when provider does not rotate it', async () => {
    const { client, storage } = setup({
      initialTokens: { access_token: 'old', refresh_token: 'rt-keep', expires_at: 1_700_000_000 },
      fetchScript: [{ status: 200, body: { access_token: 'new', expires_in: 3600 } }],
    });
    await client.refreshAccessToken();
    assert.equal(storage._peek('acme').refresh_token, 'rt-keep');
  });

  it('saves rotated refresh_token when provider returns one', async () => {
    const { client, storage } = setup({
      initialTokens: { access_token: 'old', refresh_token: 'rt-old', expires_at: 1_700_000_000 },
      fetchScript: [
        { status: 200, body: { access_token: 'new', refresh_token: 'rt-new', expires_in: 3600 } },
      ],
    });
    await client.refreshAccessToken();
    assert.equal(storage._peek('acme').refresh_token, 'rt-new');
  });

  it('throws OAuthRefreshError with requiresReauth=true on HTTP 400', async () => {
    const { client, storage } = setup({
      initialTokens: { access_token: 'a', refresh_token: 'rt', expires_at: 1_700_000_000 },
      fetchScript: [{ status: 400, body: { error: 'invalid_grant' } }],
    });
    try {
      await client.refreshAccessToken();
      assert.fail('should have thrown');
    } catch (err) {
      assert.ok(err instanceof OAuthRefreshError);
      assert.equal(err.status, 400);
      assert.equal(err.requiresReauth, true);
    }
    // Storage MUST NOT be auto-deleted — caller decides cleanup.
    assert.notEqual(storage._peek('acme'), null, 'tokens still in storage after refresh failure');
    assert.equal(storage.calls.delete, 0, 'storage.delete must not be called by toolkit');
  });

  it('throws OAuthRefreshError with requiresReauth=true on HTTP 401', async () => {
    const { client } = setup({
      initialTokens: { access_token: 'a', refresh_token: 'rt', expires_at: 1_700_000_000 },
      fetchScript: [{ status: 401, body: { error: 'unauthorized' } }],
    });
    try {
      await client.refreshAccessToken();
      assert.fail('should have thrown');
    } catch (err) {
      assert.equal(err.status, 401);
      assert.equal(err.requiresReauth, true);
    }
  });

  it('throws OAuthRefreshError with requiresReauth=false on HTTP 500 (transient)', async () => {
    const { client } = setup({
      initialTokens: { access_token: 'a', refresh_token: 'rt', expires_at: 1_700_000_000 },
      fetchScript: [{ status: 500, body: { error: 'internal' } }],
    });
    try {
      await client.refreshAccessToken();
      assert.fail('should have thrown');
    } catch (err) {
      assert.equal(err.status, 500);
      assert.equal(err.requiresReauth, false);
    }
  });

  it('throws OAuthRefreshError with requiresReauth=true when no refresh_token stored', async () => {
    const { client } = setup({
      initialTokens: { access_token: 'a', refresh_token: null, expires_at: 1_700_000_000 },
      fetchScript: [],
    });
    try {
      await client.refreshAccessToken();
      assert.fail('should have thrown');
    } catch (err) {
      assert.equal(err.requiresReauth, true);
    }
  });

  it('throws OAuthRefreshError on network error with cause', async () => {
    const netErr = new Error('ECONNREFUSED');
    const { client } = setup({
      initialTokens: { access_token: 'a', refresh_token: 'rt', expires_at: 1_700_000_000 },
      fetchScript: [{ throws: netErr }],
    });
    try {
      await client.refreshAccessToken();
      assert.fail('should have thrown');
    } catch (err) {
      assert.ok(err instanceof OAuthRefreshError);
      assert.equal(err.cause, netErr);
    }
  });
});

describe('refreshAccessToken — promise coalescing', () => {
  it('concurrent calls share a single in-flight request', async () => {
    let resolveFetch;
    const fetchPromise = new Promise((resolve) => {
      resolveFetch = resolve;
    });
    const fetchImpl = async () => fetchPromise;
    const storage = makeMemoryStorage({
      acme: { access_token: 'old', refresh_token: 'rt', expires_at: 1_700_000_000 },
    });
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: 'cid',
      clientSecret: 'sec',
      redirectUri: 'http://localhost:3000/cb',
      storage,
      options: { fetch: fetchImpl, now: () => 1_700_000_000_000 },
    });

    // Fire 5 concurrent refreshes
    const promises = [
      c.refreshAccessToken(),
      c.refreshAccessToken(),
      c.refreshAccessToken(),
      c.refreshAccessToken(),
      c.refreshAccessToken(),
    ];

    // Only one fetch should have been triggered.
    // Now resolve the single fetch.
    resolveFetch({
      ok: true,
      status: 200,
      async text() {
        return JSON.stringify({ access_token: 'fresh', expires_in: 3600 });
      },
    });

    const results = await Promise.all(promises);
    // All five should observe the same access_token.
    assert.deepEqual(results, ['fresh', 'fresh', 'fresh', 'fresh', 'fresh']);
    // Storage saved exactly once.
    assert.equal(storage.calls.save, 1, 'refresh body persisted exactly once');
  });

  it('coalesced failure propagates to all concurrent callers', async () => {
    let rejectFetch;
    const fetchPromise = new Promise((_, reject) => {
      rejectFetch = reject;
    });
    const fetchImpl = async () => fetchPromise;
    const storage = makeMemoryStorage({
      acme: { access_token: 'old', refresh_token: 'rt', expires_at: 1_700_000_000 },
    });
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: 'cid',
      clientSecret: 'sec',
      redirectUri: 'http://localhost:3000/cb',
      storage,
      options: { fetch: fetchImpl, now: () => 1_700_000_000_000 },
    });

    const promises = [c.refreshAccessToken(), c.refreshAccessToken(), c.refreshAccessToken()];
    rejectFetch(new Error('boom'));

    const results = await Promise.allSettled(promises);
    for (const r of results) {
      assert.equal(r.status, 'rejected');
      assert.ok(r.reason instanceof OAuthRefreshError);
    }
  });

  it('a fresh refresh after a failed coalesced batch is independent', async () => {
    // First batch fails; second batch should NOT inherit the failure.
    const responses = [
      { throws: new Error('first attempt fails') },
      { status: 200, body: { access_token: 'second', expires_in: 3600 } },
    ];
    const { client } = setup({
      initialTokens: { access_token: 'a', refresh_token: 'rt', expires_at: 1_700_000_000 },
      fetchScript: responses,
    });
    await assert.rejects(() => client.refreshAccessToken(), OAuthRefreshError);
    // refreshPromise should now be cleared — second call triggers a new fetch.
    const tok = await client.refreshAccessToken();
    assert.equal(tok, 'second');
  });
});
