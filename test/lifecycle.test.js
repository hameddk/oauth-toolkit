import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { createOAuthClient } from '../src/index.js';
import { acmeProvider, makeMemoryStorage, makeScriptedFetch, makeClock } from './_helpers.js';

function build({ provider = {}, fetchScript = [], clock = makeClock(), initial, options = {} } = {}) {
  const storage = makeMemoryStorage(initial ? { acme: initial } : {});
  const { fetch, calls } = makeScriptedFetch(fetchScript);
  const c = createOAuthClient({
    provider: acmeProvider(provider),
    clientId: 'cid',
    clientSecret: 'sec',
    redirectUri: 'http://localhost:3000/cb',
    storage,
    options: { fetch, now: clock.now, ...options },
  });
  return { client: c, storage, calls, clock };
}

describe('getValidAccessToken', () => {
  it('returns null when no tokens stored', async () => {
    const { client } = build();
    assert.equal(await client.getValidAccessToken(), null);
  });

  it('returns stored token when not near expiry', async () => {
    const clock = makeClock(1_700_000_000);
    const { client } = build({
      clock,
      initial: { access_token: 'a', refresh_token: 'rt', expires_at: clock.nowSec() + 3600 },
    });
    assert.equal(await client.getValidAccessToken(), 'a');
  });

  it('refreshes when within refreshLeadTimeSec window', async () => {
    const clock = makeClock(1_700_000_000);
    const { client, storage } = build({
      clock,
      initial: { access_token: 'old', refresh_token: 'rt', expires_at: clock.nowSec() + 60 },
      fetchScript: [{ status: 200, body: { access_token: 'fresh', expires_in: 3600 } }],
    });
    assert.equal(await client.getValidAccessToken(), 'fresh');
    assert.equal(storage._peek('acme').access_token, 'fresh');
  });

  it('returns null on refresh failure (does not throw)', async () => {
    const clock = makeClock(1_700_000_000);
    const { client, storage } = build({
      clock,
      initial: { access_token: 'old', refresh_token: 'rt', expires_at: clock.nowSec() + 60 },
      fetchScript: [{ status: 400, body: { error: 'invalid_grant' } }],
    });
    assert.equal(await client.getValidAccessToken(), null);
    // tokens still stored — no auto-delete
    assert.notEqual(storage._peek('acme'), null);
  });

  it('returns null when expired and no refresh_token', async () => {
    const clock = makeClock(1_700_000_000);
    const { client } = build({
      clock,
      initial: { access_token: 'a', refresh_token: null, expires_at: clock.nowSec() - 60 },
    });
    assert.equal(await client.getValidAccessToken(), null);
  });
});

describe('ensureTokenFresh', () => {
  it('no-op when token has plenty of lifetime', async () => {
    const clock = makeClock(1_700_000_000);
    const { client, calls } = build({
      clock,
      initial: { access_token: 'a', refresh_token: 'rt', expires_at: clock.nowSec() + 7200 },
    });
    await client.ensureTokenFresh();
    assert.equal(calls.length, 0);
  });

  it('refreshes when within proactive threshold (default 35min)', async () => {
    const clock = makeClock(1_700_000_000);
    const { client, calls } = build({
      clock,
      initial: { access_token: 'a', refresh_token: 'rt', expires_at: clock.nowSec() + 600 }, // 10min
      fetchScript: [{ status: 200, body: { access_token: 'fresh', expires_in: 3600 } }],
    });
    await client.ensureTokenFresh();
    assert.equal(calls.length, 1);
  });

  it('no-op when no refresh_token stored', async () => {
    const clock = makeClock(1_700_000_000);
    const { client, calls } = build({
      clock,
      initial: { access_token: 'a', refresh_token: null, expires_at: clock.nowSec() + 100 },
    });
    await client.ensureTokenFresh();
    assert.equal(calls.length, 0);
  });

  it('swallows errors and forwards to onRefreshError', async () => {
    const clock = makeClock(1_700_000_000);
    const errors = [];
    const { client } = build({
      clock,
      initial: { access_token: 'a', refresh_token: 'rt', expires_at: clock.nowSec() + 60 },
      fetchScript: [{ status: 400, body: { error: 'invalid_grant' } }],
      options: { onRefreshError: (e) => errors.push(e) },
    });
    await assert.doesNotReject(() => client.ensureTokenFresh());
    assert.equal(errors.length, 1);
    assert.equal(errors[0].requiresReauth, true);
  });

  it('coalesces concurrent ensure calls into one fetch', async () => {
    let resolveFetch;
    const fetchPromise = new Promise((r) => {
      resolveFetch = r;
    });
    const fetchImpl = async () => fetchPromise;
    const storage = makeMemoryStorage({
      acme: { access_token: 'old', refresh_token: 'rt', expires_at: 1_700_000_000 + 60 },
    });
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: 'cid',
      clientSecret: 'sec',
      redirectUri: 'http://localhost:3000/cb',
      storage,
      options: { fetch: fetchImpl, now: () => 1_700_000_000 * 1000 },
    });
    const all = [c.ensureTokenFresh(), c.ensureTokenFresh(), c.ensureTokenFresh()];
    resolveFetch({
      ok: true,
      status: 200,
      async text() {
        return JSON.stringify({ access_token: 'fresh', expires_in: 3600 });
      },
    });
    await Promise.all(all);
    assert.equal(storage.calls.save, 1, 'only one save despite three ensures');
  });
});

describe('getConnectionStatus', () => {
  it('returns not_connected when no tokens', async () => {
    const { client } = build();
    const s = await client.getConnectionStatus();
    assert.deepEqual(s, { status: 'not_connected', expires_at: null, updated_at: null });
  });

  it('returns connected when token is fresh', async () => {
    const clock = makeClock(1_700_000_000);
    const { client } = build({
      clock,
      initial: {
        access_token: 'a',
        refresh_token: 'rt',
        expires_at: clock.nowSec() + 3600,
        updated_at: clock.nowSec(),
      },
    });
    const s = await client.getConnectionStatus();
    assert.equal(s.status, 'connected');
    assert.equal(s.expires_at, clock.nowSec() + 3600);
    assert.equal(s.updated_at, clock.nowSec());
  });

  it('returns expired when within statusGracePeriodSec of expiry', async () => {
    const clock = makeClock(1_700_000_000);
    const { client } = build({
      clock,
      initial: { access_token: 'a', refresh_token: 'rt', expires_at: clock.nowSec() + 60 },
    });
    const s = await client.getConnectionStatus();
    assert.equal(s.status, 'expired');
  });
});

describe('long-lived tokens (Slack 365d fallback scenario)', () => {
  // Slack often issues user tokens without an `expires_in`; the toolkit
  // falls back to `defaultExpiresInSec` (caller can set this to 365 days).
  // These tests verify status + refresh logic stay sane with year-scale lifetimes.

  const ONE_YEAR_SEC = 365 * 24 * 3600;

  it('exchangeCodeForTokens uses defaultExpiresInSec for long-lived fallback', async () => {
    const clock = makeClock(1_700_000_000);
    const storage = makeMemoryStorage();
    const { fetch } = makeScriptedFetch([
      // Provider response with no `expires_in` field
      { status: 200, body: { access_token: 'xoxp-long', refresh_token: 'rt' } },
    ]);
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: 'cid',
      clientSecret: 'sec',
      redirectUri: 'http://localhost:3000/cb',
      storage,
      options: { fetch, now: clock.now, defaultExpiresInSec: ONE_YEAR_SEC },
    });
    const { state } = await c.getAuthorizationUrl();
    const result = await c.exchangeCodeForTokens('code', state);
    assert.equal(result.expires_at, clock.nowSec() + ONE_YEAR_SEC);
    assert.equal(storage._peek('acme').expires_at, clock.nowSec() + ONE_YEAR_SEC);
  });

  it('getConnectionStatus returns connected for year-long expiry', async () => {
    const clock = makeClock(1_700_000_000);
    const { client } = build({
      clock,
      initial: {
        access_token: 'xoxp-long',
        refresh_token: 'rt',
        expires_at: clock.nowSec() + ONE_YEAR_SEC,
        updated_at: clock.nowSec(),
      },
    });
    const s = await client.getConnectionStatus();
    assert.equal(s.status, 'connected');
    assert.equal(s.expires_at, clock.nowSec() + ONE_YEAR_SEC);
  });

  it('getValidAccessToken does NOT trigger refresh for year-long expiry', async () => {
    const clock = makeClock(1_700_000_000);
    // No fetch entries — any refresh attempt would throw "scripted fetch exhausted"
    const { client, calls } = build({
      clock,
      initial: {
        access_token: 'xoxp-long',
        refresh_token: 'rt',
        expires_at: clock.nowSec() + ONE_YEAR_SEC,
      },
      fetchScript: [],
    });
    assert.equal(await client.getValidAccessToken(), 'xoxp-long');
    assert.equal(calls.length, 0, 'no refresh request issued for year-long tokens');
  });

  it('ensureTokenFresh is a no-op for year-long expiry', async () => {
    const clock = makeClock(1_700_000_000);
    const { client, calls } = build({
      clock,
      initial: {
        access_token: 'xoxp-long',
        refresh_token: 'rt',
        expires_at: clock.nowSec() + ONE_YEAR_SEC,
      },
      fetchScript: [],
    });
    await client.ensureTokenFresh();
    assert.equal(calls.length, 0);
  });

  it('long-lived token eventually expires and triggers refresh near expiry', async () => {
    const clock = makeClock(1_700_000_000);
    const { client, calls } = build({
      clock,
      initial: {
        access_token: 'xoxp-long',
        refresh_token: 'rt',
        expires_at: clock.nowSec() + ONE_YEAR_SEC,
      },
      fetchScript: [{ status: 200, body: { access_token: 'fresh', expires_in: ONE_YEAR_SEC } }],
    });
    // Jump forward to 60 sec before expiry — within refreshLeadTimeSec (300s default)
    clock.advanceSec(ONE_YEAR_SEC - 60);
    const tok = await client.getValidAccessToken();
    assert.equal(tok, 'fresh');
    assert.equal(calls.length, 1);
  });
});

describe('disconnect', () => {
  it('deletes tokens via storage adapter', async () => {
    const { client, storage } = build({
      initial: { access_token: 'a', refresh_token: 'rt', expires_at: 1_700_000_000 },
    });
    await client.disconnect();
    assert.equal(storage._peek('acme'), null);
    assert.equal(storage.calls.delete, 1);
  });
});
