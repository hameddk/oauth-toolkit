import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  OAuthError,
  OAuthConfigError,
  OAuthStateError,
  OAuthTokenExchangeError,
  OAuthRefreshError,
  generatePkcePair,
  generateState,
} from '../src/index.js';

describe('error classes', () => {
  it('all extend OAuthError', () => {
    assert.ok(new OAuthConfigError('x') instanceof OAuthError);
    assert.ok(new OAuthStateError('x') instanceof OAuthError);
    assert.ok(new OAuthTokenExchangeError('x') instanceof OAuthError);
    assert.ok(new OAuthRefreshError('x') instanceof OAuthError);
  });

  it('all extend the built-in Error', () => {
    assert.ok(new OAuthError('x') instanceof Error);
    assert.ok(new OAuthConfigError('x') instanceof Error);
    assert.ok(new OAuthStateError('x') instanceof Error);
    assert.ok(new OAuthTokenExchangeError('x') instanceof Error);
    assert.ok(new OAuthRefreshError('x') instanceof Error);
  });

  it('have correct name fields', () => {
    assert.equal(new OAuthError('x').name, 'OAuthError');
    assert.equal(new OAuthConfigError('x').name, 'OAuthConfigError');
    assert.equal(new OAuthStateError('x').name, 'OAuthStateError');
    assert.equal(new OAuthTokenExchangeError('x').name, 'OAuthTokenExchangeError');
    assert.equal(new OAuthRefreshError('x').name, 'OAuthRefreshError');
  });

  it('OAuthTokenExchangeError carries status + body', () => {
    const err = new OAuthTokenExchangeError('boom', { status: 400, body: 'invalid_grant' });
    assert.equal(err.status, 400);
    assert.equal(err.body, 'invalid_grant');
  });

  it('OAuthRefreshError defaults requiresReauth to false', () => {
    const err = new OAuthRefreshError('boom');
    assert.equal(err.requiresReauth, false);
  });

  it('OAuthRefreshError carries requiresReauth flag when set', () => {
    const err = new OAuthRefreshError('boom', { status: 400, requiresReauth: true });
    assert.equal(err.requiresReauth, true);
    assert.equal(err.status, 400);
  });

  it('preserves cause when provided', () => {
    const cause = new Error('underlying');
    const err = new OAuthError('wrap', { cause });
    assert.equal(err.cause, cause);
  });
});

describe('generatePkcePair', () => {
  it('returns base64url-encoded verifier and challenge', () => {
    const { codeVerifier, codeChallenge } = generatePkcePair();
    assert.match(codeVerifier, /^[A-Za-z0-9_-]+$/);
    assert.match(codeChallenge, /^[A-Za-z0-9_-]+$/);
    assert.ok(codeVerifier.length >= 43, 'verifier ≥ 43 chars per RFC 7636');
    assert.equal(codeChallenge.length, 43, 'S256 challenge is 43 base64url chars');
  });

  it('produces unique pairs across calls', () => {
    const a = generatePkcePair();
    const b = generatePkcePair();
    assert.notEqual(a.codeVerifier, b.codeVerifier);
    assert.notEqual(a.codeChallenge, b.codeChallenge);
  });
});

describe('generateState', () => {
  it('produces base64url-safe strings', () => {
    const s = generateState();
    assert.match(s, /^[A-Za-z0-9_-]+$/);
  });

  it('produces unique values across calls', () => {
    const a = generateState();
    const b = generateState();
    assert.notEqual(a, b);
  });

  it('respects the bytes argument', () => {
    const small = generateState(8);
    const big = generateState(48);
    assert.ok(big.length > small.length);
  });
});
