import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { createOAuthClient, OAuthConfigError } from '../src/index.js';
import { acmeProvider, makeMemoryStorage } from './_helpers.js';

const baseOpts = () => ({
  provider: acmeProvider(),
  clientId: 'cid',
  redirectUri: 'http://localhost:3000/cb',
  storage: makeMemoryStorage(),
});

describe('createOAuthClient — config validation', () => {
  it('throws OAuthConfigError on missing options object', () => {
    assert.throws(() => createOAuthClient(), OAuthConfigError);
  });

  it('throws OAuthConfigError on missing provider', () => {
    const o = baseOpts();
    delete o.provider;
    assert.throws(() => createOAuthClient(o), OAuthConfigError);
  });

  it('throws OAuthConfigError on missing provider.name', () => {
    const o = baseOpts();
    delete o.provider.name;
    assert.throws(() => createOAuthClient(o), OAuthConfigError);
  });

  it('throws OAuthConfigError on missing provider.authorizationUrl', () => {
    const o = baseOpts();
    delete o.provider.authorizationUrl;
    assert.throws(() => createOAuthClient(o), OAuthConfigError);
  });

  it('throws OAuthConfigError on missing provider.tokenUrl', () => {
    const o = baseOpts();
    delete o.provider.tokenUrl;
    assert.throws(() => createOAuthClient(o), OAuthConfigError);
  });

  it('throws OAuthConfigError on missing clientId', () => {
    const o = baseOpts();
    delete o.clientId;
    assert.throws(() => createOAuthClient(o), OAuthConfigError);
  });

  it('throws OAuthConfigError on missing redirectUri', () => {
    const o = baseOpts();
    delete o.redirectUri;
    assert.throws(() => createOAuthClient(o), OAuthConfigError);
  });

  it('throws OAuthConfigError on storage missing methods', () => {
    const o = baseOpts();
    o.storage = {};
    assert.throws(() => createOAuthClient(o), OAuthConfigError);
  });

  it('throws OAuthConfigError on invalid tokenEndpointAuth', () => {
    const o = baseOpts();
    o.provider.tokenEndpointAuth = 'totally-invalid';
    assert.throws(() => createOAuthClient(o), OAuthConfigError);
  });

  it('throws OAuthConfigError on invalid tokenEndpointFormat', () => {
    const o = baseOpts();
    o.provider.tokenEndpointFormat = 'xml';
    assert.throws(() => createOAuthClient(o), OAuthConfigError);
  });

  it('builds a client with minimal valid config', () => {
    const c = createOAuthClient(baseOpts());
    assert.equal(typeof c.getAuthorizationUrl, 'function');
    assert.equal(typeof c.exchangeCodeForTokens, 'function');
    assert.equal(typeof c.getValidAccessToken, 'function');
    assert.equal(typeof c.refreshAccessToken, 'function');
    assert.equal(typeof c.ensureTokenFresh, 'function');
    assert.equal(typeof c.getConnectionStatus, 'function');
    assert.equal(typeof c.disconnect, 'function');
  });
});
