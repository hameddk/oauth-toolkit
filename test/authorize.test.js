import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { createOAuthClient, OAuthConfigError } from '../src/index.js';
import { acmeProvider, makeMemoryStorage } from './_helpers.js';

function parseUrl(u) {
  const url = new URL(u);
  const params = Object.fromEntries(url.searchParams.entries());
  return { url, params };
}

describe('getAuthorizationUrl', () => {
  it('builds authorize URL with required OAuth params (no PKCE)', async () => {
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: 'cid-123',
      redirectUri: 'http://localhost:3000/cb',
      storage: makeMemoryStorage(),
    });
    const { url, state } = await c.getAuthorizationUrl();
    const { url: parsed, params } = parseUrl(url);

    assert.equal(parsed.origin + parsed.pathname, 'https://auth.acme.example/oauth/authorize');
    assert.equal(params.response_type, 'code');
    assert.equal(params.client_id, 'cid-123');
    assert.equal(params.redirect_uri, 'http://localhost:3000/cb');
    assert.equal(params.state, state);
    assert.equal(params.scope, 'read write');
    assert.equal(params.code_challenge, undefined);
    assert.equal(params.code_challenge_method, undefined);
  });

  it('includes PKCE code_challenge + S256 method when pkce: true', async () => {
    const c = createOAuthClient({
      provider: acmeProvider({ pkce: true }),
      clientId: 'cid',
      redirectUri: 'http://localhost:3000/cb',
      storage: makeMemoryStorage(),
    });
    const { url } = await c.getAuthorizationUrl();
    const { params } = parseUrl(url);
    assert.match(params.code_challenge, /^[A-Za-z0-9_-]+$/);
    assert.equal(params.code_challenge.length, 43);
    assert.equal(params.code_challenge_method, 'S256');
  });

  it('honors comma scope separator (Slack-style)', async () => {
    const c = createOAuthClient({
      provider: acmeProvider({ scopes: ['chat:write', 'im:read'], scopeSeparator: ',' }),
      clientId: 'cid',
      redirectUri: 'http://localhost:3000/cb',
      storage: makeMemoryStorage(),
    });
    const { url } = await c.getAuthorizationUrl();
    const { params } = parseUrl(url);
    assert.equal(params.scope, 'chat:write,im:read');
  });

  it('includes extraAuthParams', async () => {
    const c = createOAuthClient({
      provider: acmeProvider({
        extraAuthParams: { audience: 'api.acme.example', prompt: 'consent' },
      }),
      clientId: 'cid',
      redirectUri: 'http://localhost:3000/cb',
      storage: makeMemoryStorage(),
    });
    const { url } = await c.getAuthorizationUrl();
    const { params } = parseUrl(url);
    assert.equal(params.audience, 'api.acme.example');
    assert.equal(params.prompt, 'consent');
  });

  it('omits scope param when scopes is missing', async () => {
    const c = createOAuthClient({
      provider: acmeProvider({ scopes: undefined }),
      clientId: 'cid',
      redirectUri: 'http://localhost:3000/cb',
      storage: makeMemoryStorage(),
    });
    const { url } = await c.getAuthorizationUrl();
    const { params } = parseUrl(url);
    assert.equal(params.scope, undefined);
  });

  it('accepts scope as a pre-joined string', async () => {
    const c = createOAuthClient({
      provider: acmeProvider({ scopes: 'a:b c:d' }),
      clientId: 'cid',
      redirectUri: 'http://localhost:3000/cb',
      storage: makeMemoryStorage(),
    });
    const { url } = await c.getAuthorizationUrl();
    const { params } = parseUrl(url);
    assert.equal(params.scope, 'a:b c:d');
  });

  it('produces a unique state for each call', async () => {
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: 'cid',
      redirectUri: 'http://localhost:3000/cb',
      storage: makeMemoryStorage(),
    });
    const a = await c.getAuthorizationUrl();
    const b = await c.getAuthorizationUrl();
    assert.notEqual(a.state, b.state);
  });

  it('uses dynamic redirectUri function', async () => {
    let host = 'http://localhost:3000';
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: 'cid',
      redirectUri: () => `${host}/cb`,
      storage: makeMemoryStorage(),
    });
    const a = await c.getAuthorizationUrl();
    assert.equal(parseUrl(a.url).params.redirect_uri, 'http://localhost:3000/cb');
    host = 'https://abc.ngrok.app';
    const b = await c.getAuthorizationUrl();
    assert.equal(parseUrl(b.url).params.redirect_uri, 'https://abc.ngrok.app/cb');
  });

  it('throws OAuthConfigError when redirectUri function returns empty', async () => {
    const c = createOAuthClient({
      provider: acmeProvider(),
      clientId: 'cid',
      redirectUri: () => '',
      storage: makeMemoryStorage(),
    });
    await assert.rejects(() => c.getAuthorizationUrl(), OAuthConfigError);
  });
});
