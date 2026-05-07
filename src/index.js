/**
 * @hameddk/oauth-toolkit — provider-agnostic OAuth 2.0 client.
 *
 * No DB, no filesystem, no provider knowledge baked in.
 * Caller supplies provider config + storage adapter.
 */

import { randomBytes, createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Base error class. All toolkit-thrown errors extend this. */
export class OAuthError extends Error {
  constructor(message, { cause } = {}) {
    super(message);
    this.name = 'OAuthError';
    if (cause) this.cause = cause;
  }
}

/** Missing or invalid configuration (e.g. clientId not provided). */
export class OAuthConfigError extends OAuthError {
  constructor(message, opts) {
    super(message, opts);
    this.name = 'OAuthConfigError';
  }
}

/** State parameter not found in pending map (CSRF protection or expired TTL). */
export class OAuthStateError extends OAuthError {
  constructor(message, opts) {
    super(message, opts);
    this.name = 'OAuthStateError';
  }
}

/** Authorization-code → token exchange failed. */
export class OAuthTokenExchangeError extends OAuthError {
  constructor(message, { status, body, cause } = {}) {
    super(message, { cause });
    this.name = 'OAuthTokenExchangeError';
    this.status = status;
    this.body = body;
  }
}

/**
 * Refresh-token grant failed (or no refresh_token stored).
 * `requiresReauth` is true when the provider returned 400/401 — caller should
 * surface a "reconnect" UX. Toolkit never auto-deletes storage; caller decides.
 */
export class OAuthRefreshError extends OAuthError {
  constructor(message, { status, body, cause, requiresReauth = false } = {}) {
    super(message, { cause });
    this.name = 'OAuthRefreshError';
    this.status = status;
    this.body = body;
    this.requiresReauth = requiresReauth;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function base64UrlEncode(buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Generate a PKCE code_verifier (43+ char) + S256 code_challenge.
 * Exposed for advanced callers.
 *
 * @returns {{codeVerifier: string, codeChallenge: string}}
 */
export function generatePkcePair() {
  const codeVerifier = base64UrlEncode(randomBytes(32));
  const hash = createHash('sha256').update(codeVerifier).digest();
  const codeChallenge = base64UrlEncode(hash);
  return { codeVerifier, codeChallenge };
}

/**
 * URL-safe random state string.
 *
 * @param {number} [bytes=24]
 * @returns {string}
 */
export function generateState(bytes = 24) {
  return base64UrlEncode(randomBytes(bytes));
}

/** Resolve a value-or-resolver. Wraps thrown errors in OAuthConfigError. */
async function resolveCredential(value, name) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'function') return value;
  try {
    const result = await value();
    return result ?? null;
  } catch (cause) {
    throw new OAuthConfigError(`Failed to resolve ${name}: ${cause.message}`, { cause });
  }
}

function nowSec(now) {
  return Math.floor(now() / 1000);
}

/**
 * Validate a string is a parseable absolute URL. Throws OAuthConfigError if not.
 */
function assertValidUrl(value, label) {
  try {
    // URL constructor throws on invalid input.
    new URL(value);
  } catch {
    throw new OAuthConfigError(`${label} is not a valid URL: ${value}`);
  }
}

/**
 * Normalize provider.tokenUrl into { exchange, refresh }.
 * Accepts a string (used for both endpoints) or an object with both fields.
 */
function normalizeTokenUrl(tokenUrl) {
  if (typeof tokenUrl === 'string') {
    return { exchange: tokenUrl, refresh: tokenUrl };
  }
  if (tokenUrl && typeof tokenUrl === 'object') {
    const { exchange, refresh } = tokenUrl;
    if (typeof exchange !== 'string' || !exchange) {
      throw new OAuthConfigError('provider.tokenUrl.exchange is required when tokenUrl is an object');
    }
    if (typeof refresh !== 'string' || !refresh) {
      throw new OAuthConfigError('provider.tokenUrl.refresh is required when tokenUrl is an object');
    }
    assertValidUrl(exchange, 'provider.tokenUrl.exchange');
    assertValidUrl(refresh, 'provider.tokenUrl.refresh');
    return { exchange, refresh };
  }
  throw new OAuthConfigError('provider.tokenUrl must be a string or { exchange, refresh } object');
}

// ---------------------------------------------------------------------------
// State store with TTL + passive cleanup
// ---------------------------------------------------------------------------

class StateStore {
  /**
   * @param {number} ttlMs
   * @param {() => number} now  Returns ms.
   */
  constructor(ttlMs, now) {
    this._map = new Map();
    this._ttlMs = ttlMs;
    this._now = now;
  }

  set(key, value) {
    this._cleanup();
    this._map.set(key, { value, expiresAt: this._now() + this._ttlMs });
  }

  get(key) {
    const entry = this._map.get(key);
    if (!entry) return null;
    if (entry.expiresAt < this._now()) {
      this._map.delete(key);
      return null;
    }
    return entry.value;
  }

  delete(key) {
    this._map.delete(key);
  }

  size() {
    return this._map.size;
  }

  _cleanup() {
    const t = this._now();
    for (const [k, v] of this._map) {
      if (v.expiresAt < t) this._map.delete(k);
    }
  }
}

// ---------------------------------------------------------------------------
// Types (JSDoc)
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} ProviderConfig
 * @property {string} name
 * @property {string} authorizationUrl
 * @property {string|{exchange: string, refresh: string}} tokenUrl
 *   Either a single URL used for both code exchange and refresh (the common case),
 *   or an object with separate URLs for providers that split these endpoints.
 * @property {string|string[]} [scopes]
 * @property {string} [scopeSeparator=' ']
 * @property {boolean} [pkce=false]
 * @property {'body'|'basic'|'none'} [tokenEndpointAuth='body']
 * @property {'form'|'json'} [tokenEndpointFormat='form']
 * @property {Record<string,string>} [extraAuthParams]
 * @property {(data: any) => {access_token: string, refresh_token?: string, expires_in?: number}} [parseTokenResponse]
 */

/**
 * @typedef {Object} StoredTokens
 * @property {string} access_token
 * @property {string|null} [refresh_token]
 * @property {number} expires_at  Unix seconds.
 * @property {number} [updated_at]
 */

/**
 * @typedef {Object} StorageAdapter
 * @property {(provider: string) => Promise<StoredTokens|null>} load
 * @property {(provider: string, tokens: StoredTokens) => Promise<void>} save
 * @property {(provider: string) => Promise<void>} delete
 */

/**
 * @typedef {Object} ClientOptions
 * @property {ProviderConfig} provider
 * @property {string|(() => string|Promise<string>)} clientId
 * @property {string|(() => string|Promise<string|null>)} [clientSecret]
 * @property {string|(() => string)} redirectUri
 * @property {StorageAdapter} storage
 * @property {Object} [options]
 * @property {number} [options.proactiveRefreshThresholdSec=2100]
 * @property {number} [options.refreshLeadTimeSec=300]
 * @property {number} [options.defaultExpiresInSec=3600]
 * @property {number} [options.statusGracePeriodSec=300]
 * @property {number} [options.stateTtlMs=600000]
 * @property {(err: Error) => void} [options.onRefreshError]
 * @property {typeof fetch} [options.fetch]      For testing only.
 * @property {() => number} [options.now]        For testing only. Returns Unix milliseconds.
 */

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create an OAuth client.
 *
 * @param {ClientOptions} opts
 */
export function createOAuthClient(opts) {
  if (!opts || typeof opts !== 'object') {
    throw new OAuthConfigError('createOAuthClient: options object is required');
  }
  const { provider, clientId, clientSecret, redirectUri, storage } = opts;
  const userOptions = opts.options ?? {};

  if (!provider || typeof provider !== 'object') {
    throw new OAuthConfigError('provider config is required');
  }
  if (!provider.name) throw new OAuthConfigError('provider.name is required');
  if (!provider.authorizationUrl) throw new OAuthConfigError('provider.authorizationUrl is required');
  if (!provider.tokenUrl) throw new OAuthConfigError('provider.tokenUrl is required');
  const tokenUrls = normalizeTokenUrl(provider.tokenUrl);
  if (clientId === undefined || clientId === null) throw new OAuthConfigError('clientId is required');
  if (!redirectUri) throw new OAuthConfigError('redirectUri is required');
  if (
    !storage ||
    typeof storage.load !== 'function' ||
    typeof storage.save !== 'function' ||
    typeof storage.delete !== 'function'
  ) {
    throw new OAuthConfigError('storage adapter must implement load(), save(), delete()');
  }

  const cfg = {
    provider: {
      pkce: false,
      tokenEndpointAuth: 'body',
      tokenEndpointFormat: 'form',
      scopeSeparator: ' ',
      ...provider,
    },
    refreshLeadTimeSec: userOptions.refreshLeadTimeSec ?? 300,
    proactiveRefreshThresholdSec: userOptions.proactiveRefreshThresholdSec ?? 35 * 60,
    defaultExpiresInSec: userOptions.defaultExpiresInSec ?? 3600,
    statusGracePeriodSec: userOptions.statusGracePeriodSec ?? 300,
    stateTtlMs: userOptions.stateTtlMs ?? 10 * 60 * 1000,
    onRefreshError: userOptions.onRefreshError ?? (() => {}),
    fetch: userOptions.fetch ?? globalThis.fetch,
    now: userOptions.now ?? (() => Date.now()),
  };

  if (typeof cfg.fetch !== 'function') {
    throw new OAuthConfigError('options.fetch is not a function (and globalThis.fetch is unavailable)');
  }

  const validAuthModes = ['body', 'basic', 'none'];
  if (!validAuthModes.includes(cfg.provider.tokenEndpointAuth)) {
    throw new OAuthConfigError(
      `provider.tokenEndpointAuth must be one of ${validAuthModes.join('|')}, got "${cfg.provider.tokenEndpointAuth}"`
    );
  }
  const validFormats = ['form', 'json'];
  if (!validFormats.includes(cfg.provider.tokenEndpointFormat)) {
    throw new OAuthConfigError(
      `provider.tokenEndpointFormat must be one of ${validFormats.join('|')}, got "${cfg.provider.tokenEndpointFormat}"`
    );
  }

  const stateStore = new StateStore(cfg.stateTtlMs, cfg.now);
  let refreshPromise = null;

  function resolveRedirectUri() {
    const url = typeof redirectUri === 'function' ? redirectUri() : redirectUri;
    if (!url) throw new OAuthConfigError('redirectUri resolved to empty value');
    return url;
  }

  function parseTokens(data) {
    if (typeof cfg.provider.parseTokenResponse === 'function') {
      const parsed = cfg.provider.parseTokenResponse(data) ?? {};
      return {
        access_token: parsed.access_token ?? null,
        refresh_token: parsed.refresh_token ?? null,
        expires_in: parsed.expires_in,
      };
    }
    return {
      access_token: data?.access_token ?? null,
      refresh_token: data?.refresh_token ?? null,
      expires_in: data?.expires_in,
    };
  }

  function computeExpiresAt(expiresIn) {
    const t = nowSec(cfg.now);
    const num = Number(expiresIn);
    const inSec = Number.isFinite(num) ? num : cfg.defaultExpiresInSec;
    return t + inSec;
  }

  async function buildTokenRequest(grantParams) {
    const id = await resolveCredential(clientId, 'clientId');
    if (!id) throw new OAuthConfigError('clientId resolved to empty value');
    const secret = await resolveCredential(clientSecret, 'clientSecret');

    const headers = { Accept: 'application/json' };
    const params = { ...grantParams };

    if (cfg.provider.tokenEndpointAuth === 'basic') {
      if (!secret) throw new OAuthConfigError('tokenEndpointAuth "basic" requires clientSecret');
      const basic = Buffer.from(`${id}:${secret}`).toString('base64');
      headers.Authorization = `Basic ${basic}`;
    } else {
      params.client_id = id;
      if (cfg.provider.tokenEndpointAuth === 'body' && secret) {
        params.client_secret = secret;
      }
    }

    let body;
    if (cfg.provider.tokenEndpointFormat === 'json') {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(params);
    } else {
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      body = new URLSearchParams(params).toString();
    }
    return { headers, body };
  }

  async function getAuthorizationUrl() {
    const id = await resolveCredential(clientId, 'clientId');
    if (!id) throw new OAuthConfigError('clientId resolved to empty value');

    const url = resolveRedirectUri();
    const state = generateState();

    let codeVerifier = null;
    let codeChallenge = null;
    if (cfg.provider.pkce) {
      const pair = generatePkcePair();
      codeVerifier = pair.codeVerifier;
      codeChallenge = pair.codeChallenge;
    }

    stateStore.set(state, { codeVerifier, redirectUri: url });

    const params = new URLSearchParams();
    params.set('response_type', 'code');
    params.set('client_id', id);
    params.set('redirect_uri', url);
    params.set('state', state);

    if (cfg.provider.scopes != null) {
      const scope = Array.isArray(cfg.provider.scopes)
        ? cfg.provider.scopes.join(cfg.provider.scopeSeparator)
        : String(cfg.provider.scopes);
      if (scope) params.set('scope', scope);
    }

    if (cfg.provider.pkce && codeChallenge) {
      params.set('code_challenge', codeChallenge);
      params.set('code_challenge_method', 'S256');
    }

    if (cfg.provider.extraAuthParams) {
      for (const [k, v] of Object.entries(cfg.provider.extraAuthParams)) {
        if (v !== undefined && v !== null) params.set(k, String(v));
      }
    }

    return {
      url: `${cfg.provider.authorizationUrl}?${params.toString()}`,
      state,
    };
  }

  async function exchangeCodeForTokens(code, state) {
    if (!code) throw new OAuthError('code is required');
    if (!state) throw new OAuthError('state is required');

    const pending = stateStore.get(state);
    if (!pending) {
      throw new OAuthStateError('Invalid or expired state');
    }
    // Always clear the entry — pkce code_verifier never reused.
    stateStore.delete(state);

    const grant = {
      grant_type: 'authorization_code',
      code: String(code),
      redirect_uri: pending.redirectUri,
    };
    if (pending.codeVerifier) grant.code_verifier = pending.codeVerifier;

    const { headers, body } = await buildTokenRequest(grant);

    let res;
    try {
      res = await cfg.fetch(tokenUrls.exchange, { method: 'POST', headers, body });
    } catch (cause) {
      throw new OAuthTokenExchangeError(`Token exchange request failed: ${cause.message}`, { cause });
    }

    const responseText = await res.text();
    let data;
    try {
      data = responseText ? JSON.parse(responseText) : {};
    } catch {
      throw new OAuthTokenExchangeError(`Token endpoint returned non-JSON (${res.status})`, {
        status: res.status,
        body: responseText,
      });
    }

    if (!res.ok) {
      throw new OAuthTokenExchangeError(`Token exchange failed (${res.status})`, {
        status: res.status,
        body: responseText,
      });
    }

    const parsed = parseTokens(data);
    if (!parsed.access_token) {
      throw new OAuthTokenExchangeError('Token endpoint returned no access_token', {
        status: res.status,
        body: responseText,
      });
    }

    const expiresAt = computeExpiresAt(parsed.expires_in);

    await storage.save(cfg.provider.name, {
      access_token: parsed.access_token,
      refresh_token: parsed.refresh_token ?? null,
      expires_at: expiresAt,
    });

    return {
      access_token: parsed.access_token,
      expires_at: expiresAt,
      raw: data,
    };
  }

  async function performRefresh() {
    const stored = await storage.load(cfg.provider.name);
    if (!stored?.refresh_token) {
      throw new OAuthRefreshError('No refresh token stored', { requiresReauth: true });
    }

    const grant = {
      grant_type: 'refresh_token',
      refresh_token: stored.refresh_token,
    };
    const { headers, body } = await buildTokenRequest(grant);

    let res;
    try {
      res = await cfg.fetch(tokenUrls.refresh, { method: 'POST', headers, body });
    } catch (cause) {
      throw new OAuthRefreshError(`Refresh request failed: ${cause.message}`, { cause });
    }

    const responseText = await res.text();
    let data;
    try {
      data = responseText ? JSON.parse(responseText) : {};
    } catch {
      throw new OAuthRefreshError(`Token endpoint returned non-JSON (${res.status})`, {
        status: res.status,
        body: responseText,
      });
    }

    if (!res.ok) {
      const requiresReauth = res.status === 400 || res.status === 401;
      throw new OAuthRefreshError(`Token refresh failed (${res.status})`, {
        status: res.status,
        body: responseText,
        requiresReauth,
      });
    }

    const parsed = parseTokens(data);
    if (!parsed.access_token) {
      throw new OAuthRefreshError('Refresh endpoint returned no access_token', {
        status: res.status,
        body: responseText,
      });
    }

    // Preserve old refresh_token if provider didn't rotate.
    const newRefresh = parsed.refresh_token ?? stored.refresh_token;
    const expiresAt = computeExpiresAt(parsed.expires_in);

    await storage.save(cfg.provider.name, {
      access_token: parsed.access_token,
      refresh_token: newRefresh,
      expires_at: expiresAt,
    });

    return parsed.access_token;
  }

  /**
   * Force a refresh. Coalesces concurrent calls — they all await the same promise
   * and observe the same outcome.
   */
  function refreshAccessToken() {
    if (refreshPromise) return refreshPromise;
    refreshPromise = (async () => {
      try {
        return await performRefresh();
      } finally {
        refreshPromise = null;
      }
    })();
    return refreshPromise;
  }

  async function getValidAccessToken() {
    const stored = await storage.load(cfg.provider.name);
    if (!stored) return null;

    const t = nowSec(cfg.now);
    if (stored.expires_at > t + cfg.refreshLeadTimeSec) {
      return stored.access_token;
    }
    if (!stored.refresh_token) return null;

    try {
      return await refreshAccessToken();
    } catch {
      return null;
    }
  }

  async function ensureTokenFresh() {
    const stored = await storage.load(cfg.provider.name);
    if (!stored?.refresh_token) return;

    const t = nowSec(cfg.now);
    if (stored.expires_at - t > cfg.proactiveRefreshThresholdSec) return;

    try {
      await refreshAccessToken();
    } catch (err) {
      cfg.onRefreshError(err);
    }
  }

  async function getConnectionStatus() {
    const stored = await storage.load(cfg.provider.name);
    if (!stored) return { status: 'not_connected', expires_at: null, updated_at: null };

    const t = nowSec(cfg.now);
    const expiresAt = stored.expires_at;
    const updatedAt = stored.updated_at ?? null;

    if (expiresAt > t + cfg.statusGracePeriodSec) {
      return { status: 'connected', expires_at: expiresAt, updated_at: updatedAt };
    }
    return { status: 'expired', expires_at: expiresAt, updated_at: updatedAt };
  }

  async function disconnect() {
    await storage.delete(cfg.provider.name);
  }

  return {
    getAuthorizationUrl,
    exchangeCodeForTokens,
    getValidAccessToken,
    refreshAccessToken,
    ensureTokenFresh,
    getConnectionStatus,
    disconnect,
    /** @internal Exposed for tests; subject to change. */
    _internals: {
      stateStoreSize: () => stateStore.size(),
    },
  };
}
