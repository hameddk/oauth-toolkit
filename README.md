# @hameddk/oauth-toolkit

Provider-agnostic OAuth 2.0 client toolkit for Node.js.

- Authorization Code flow — both **PKCE-only public clients** and **confidential clients with client_secret**
- Token refresh with proactive, **promise-coalesced** background refresh
- Pluggable **storage adapter** — caller controls persistence and encryption
- State store with **TTL + auto-cleanup** to prevent leaks from abandoned flows
- Refresh failures expose `requiresReauth` — toolkit never auto-deletes your storage
- No DB, no filesystem, no provider knowledge baked in
- Zero dependencies, ESM, Node ≥ 18

> Status: 0.1.0 — early. Public API is stable for the documented surface.

## Install

```bash
npm install @hameddk/oauth-toolkit
```

## Quick start

Below are two parallel examples wiring up an imaginary `acme-oauth` provider:
one **PKCE-only** (no secret), one **confidential** (with secret, no PKCE).
Real providers (your IdP, GitHub, Google, ...) follow the same shape.

### Flow A — Authorization Code + PKCE (no client secret)

```js
import { createOAuthClient } from '@hameddk/oauth-toolkit';

const client = createOAuthClient({
  provider: {
    name: 'acme',
    authorizationUrl: 'https://auth.acme.example/oauth/authorize',
    tokenUrl: 'https://auth.acme.example/oauth/token',
    scopes: ['read:profile', 'write:items'],
    pkce: true,                       // S256 code_challenge + code_verifier
    tokenEndpointAuth: 'none',        // public client — no secret
    tokenEndpointFormat: 'form',
  },
  clientId: process.env.ACME_CLIENT_ID,
  redirectUri: 'http://localhost:3000/auth/acme/callback',
  storage,                            // see "Storage adapter" below
});

const { url, state } = await client.getAuthorizationUrl();
// → open `url` in browser; user is redirected back to redirectUri with ?code=...&state=...

await client.exchangeCodeForTokens(code, state);

const accessToken = await client.getValidAccessToken();
```

### Flow B — Authorization Code + client_secret (no PKCE)

```js
import { createOAuthClient } from '@hameddk/oauth-toolkit';

const client = createOAuthClient({
  provider: {
    name: 'acme',
    authorizationUrl: 'https://auth.acme.example/oauth/authorize',
    tokenUrl: 'https://auth.acme.example/oauth/token',
    scopes: ['read:profile', 'write:items'],
    pkce: false,
    tokenEndpointAuth: 'basic',       // Authorization: Basic base64(id:secret)
    tokenEndpointFormat: 'form',
  },
  clientId: process.env.ACME_CLIENT_ID,
  clientSecret: process.env.ACME_CLIENT_SECRET,
  redirectUri: 'http://localhost:3000/auth/acme/callback',
  storage,
});

const { url, state } = await client.getAuthorizationUrl();
await client.exchangeCodeForTokens(code, state);
const accessToken = await client.getValidAccessToken();
```

PKCE and client_secret are **not mutually exclusive** — some providers
require both. Set `pkce: true` and `tokenEndpointAuth: 'body'` (or `'basic'`)
together.

## Public API

```js
const client = createOAuthClient(options);

await client.getAuthorizationUrl();              // → { url, state }
await client.exchangeCodeForTokens(code, state); // → { access_token, expires_at, raw }
await client.getValidAccessToken();              // → string | null   (refreshes if needed)
await client.refreshAccessToken();               // → string          (force; throws on fail)
await client.ensureTokenFresh();                 // → void            (proactive, coalesced)
await client.getConnectionStatus();              // → { status, expires_at, updated_at }
await client.disconnect();                       // → void
```

## Provider configuration

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | `string` | — | Storage key. Must be unique per provider. |
| `authorizationUrl` | `string` | — | OAuth authorize endpoint. |
| `tokenUrl` | `string \| { exchange, refresh }` | — | OAuth token endpoint(s). See [tokenUrl forms](#tokenurl-forms) below. |
| `scopes` | `string \| string[]` | — | Joined with `scopeSeparator` if array. |
| `scopeSeparator` | `string` | `' '` | Some providers use `','`. |
| `pkce` | `boolean` | `false` | Enable S256 PKCE. |
| `tokenEndpointAuth` | `'body' \| 'basic' \| 'none'` | `'body'` | See below. |
| `tokenEndpointFormat` | `'form' \| 'json'` | `'form'` | Body encoding. |
| `extraAuthParams` | `Record<string,string>` | — | Extra query params on the authorize URL (e.g. `audience`, `prompt`). |
| `parseTokenResponse` | `(data) => { access_token, refresh_token?, expires_in? }` | — | Override for non-standard responses (e.g. tokens nested under `authed_user`). |

### `tokenUrl` forms

Most providers use a single token endpoint for both authorization-code exchange
and refresh-token grants. Pass it as a string:

```js
provider: {
  tokenUrl: 'https://auth.acme.example/oauth/token',
  // ...
}
```

A few providers split the two operations across distinct URLs (for example,
when the user-token exchange has different scope semantics than the standard
refresh endpoint). Pass an object with both URLs in that case:

```js
provider: {
  tokenUrl: {
    exchange: 'https://auth.acme.example/oauth/user.access',  // code → tokens
    refresh:  'https://auth.acme.example/oauth/access',       // refresh_token grant
  },
  // ...
}
```

Both URLs are validated at client construction. Use the string form when in
doubt — the object form exists specifically for providers with split token
endpoints.

### `tokenEndpointAuth`

| Mode | What's sent |
|---|---|
| `'body'` | `client_id` (+ `client_secret` if supplied) in the body. |
| `'basic'` | `Authorization: Basic base64(client_id:client_secret)` header. |
| `'none'` | No client auth — typically PKCE-only public clients. |

## Storage adapter

```ts
interface StorageAdapter {
  load(provider: string): Promise<StoredTokens | null>;
  save(provider: string, tokens: StoredTokens): Promise<void>;
  delete(provider: string): Promise<void>;
}

interface StoredTokens {
  access_token: string;       // plain — adapter encrypts at rest
  refresh_token?: string;     // plain
  expires_at: number;         // Unix seconds (UTC)
  updated_at?: number;        // Unix seconds, set by adapter on save
}
```

The toolkit hands you plaintext tokens. **Encrypt them in your adapter.**
For example, wrap [@hameddk/secret-storage](https://www.npmjs.com/package/@hameddk/secret-storage)
to get AES-256-GCM at rest, then persist to whatever you like (SQLite, Postgres, file, KV).

In-memory example:

```js
const map = new Map();
const storage = {
  async load(provider) {
    return map.get(provider) ?? null;
  },
  async save(provider, tokens) {
    map.set(provider, { ...tokens, updated_at: Math.floor(Date.now() / 1000) });
  },
  async delete(provider) {
    map.delete(provider);
  },
};
```

## Lazy credentials

`clientId` and `clientSecret` accept a function (sync or async). The resolver
is called **every time** the toolkit needs the value — no internal caching.
Cache on your side if the lookup is expensive.

```js
const client = createOAuthClient({
  ...,
  clientId: () => credentialsStore.get('acme_client_id'),
  clientSecret: async () => secretsManager.get('acme_client_secret'),
});
```

If a resolver throws, the toolkit wraps the error in `OAuthConfigError` and
preserves the original cause via the standard `cause` property.

## Dynamic redirect URIs

`redirectUri` accepts a function — re-evaluated on each `getAuthorizationUrl()`
call. Useful with tunnels (ngrok, cloudflared) where the public URL changes:

```js
redirectUri: () => `${getActiveTunnelUrl() ?? 'http://localhost:3000'}/auth/acme/callback`,
```

## Refresh policy

| Method | When it refreshes | Coalescing |
|---|---|---|
| `getValidAccessToken()` | If expiring within `refreshLeadTimeSec` (default 5 min). | Shared with `refreshAccessToken()` and `ensureTokenFresh()`. |
| `ensureTokenFresh()` | If expiring within `proactiveRefreshThresholdSec` (default 35 min). Errors go to `onRefreshError`. | Shared. |
| `refreshAccessToken()` | Always. Throws on failure. | Shared. |

Concurrent calls to any of these methods all observe the **same in-flight
refresh** — only one network request per refresh window per provider.

### `requiresReauth` semantics

When a refresh fails with HTTP **400 or 401**, the toolkit throws an
`OAuthRefreshError` with `requiresReauth: true`. This is your signal to surface
a reconnect UX to the user.

**The toolkit never auto-deletes your storage.** The decision to clear stored
tokens belongs to the caller — log first, prompt the user, or keep the row for
audit. Call `disconnect()` when you're ready.

```js
try {
  await client.refreshAccessToken();
} catch (err) {
  if (err.requiresReauth) {
    // 400/401 — refresh_token revoked or expired
    showReconnectBanner();
  } else {
    // 5xx, network — likely transient
    scheduleRetry();
  }
}
```

If the provider rotates the refresh token, the toolkit saves the new value via
`storage.save()`. If the response omits `refresh_token`, the previous one is
preserved.

## State TTL

Pending OAuth flows (PKCE `code_verifier` + `redirectUri`, keyed by `state`)
are held in an in-memory map with a TTL of **10 minutes** by default
(configurable via `options.stateTtlMs`). Expired entries are pruned on every
read/write — no timers, no memory leak from abandoned redirects.

After a successful or failed `exchangeCodeForTokens()`, the state entry is
always cleared — it cannot be reused.

## Errors

```js
import {
  OAuthError,                  // base
  OAuthConfigError,            // missing/invalid config, resolver threw
  OAuthStateError,             // unknown or expired state on callback
  OAuthTokenExchangeError,     // code → token failed (status, body)
  OAuthRefreshError,           // refresh_token grant failed (status, body, requiresReauth)
} from '@hameddk/oauth-toolkit';
```

Errors carry the provider's response body (when available) but **never** echo
your `client_secret`, `code_verifier`, or `refresh_token` — those are sent in
the request, not the response.

## Testing hooks

For testing only:

```js
options: {
  fetch: customFetch,   // override fetch implementation
  now: () => 1234567890_000,  // override clock (returns Unix ms)
}
```

These exist so you can write deterministic tests without monkey-patching
globals or installing fake-timers. **Do not use them in production code.**

## Security considerations

Read these before deploying.

### 1. Plaintext tokens cross the storage-adapter boundary

The toolkit hands your `StorageAdapter.save()` plaintext `access_token` and
`refresh_token` strings. **Encryption at rest is the adapter's responsibility.**
A common pattern is to wrap
[@hameddk/secret-storage](https://www.npmjs.com/package/@hameddk/secret-storage)
(AES-256-GCM, zero deps) inside `save`/`load` so plaintext only exists in
memory at the moment of use:

```js
import { encrypt, decrypt } from '@hameddk/secret-storage';

const storage = {
  async load(name) {
    const row = await db.get('SELECT * FROM oauth_tokens WHERE provider = ?', name);
    if (!row) return null;
    return {
      access_token: decrypt(row.access_token),
      refresh_token: row.refresh_token ? decrypt(row.refresh_token) : null,
      expires_at: row.expires_at,
    };
  },
  async save(name, t) {
    await db.run(
      'INSERT OR REPLACE INTO oauth_tokens (provider, access_token, refresh_token, expires_at) VALUES (?, ?, ?, ?)',
      name,
      encrypt(t.access_token),
      t.refresh_token ? encrypt(t.refresh_token) : null,
      t.expires_at,
    );
  },
  async delete(name) {
    await db.run('DELETE FROM oauth_tokens WHERE provider = ?', name);
  },
};
```

### 2. Pending-flow state is in-memory (single-instance only in v0.1)

Between `getAuthorizationUrl()` and `exchangeCodeForTokens()`, the toolkit
holds the PKCE `code_verifier` and the resolved `redirectUri` in an in-memory
`Map`, keyed by `state`, with a 10-minute TTL.

This means **multi-instance deployments are not supported in v0.1.** If the
authorize call hits one server and the callback hits another, the second
server has no `code_verifier` and the exchange will throw `OAuthStateError`.
Single-instance use cases (Electron desktop apps, single-process backends,
sticky-session deployments) are fine.

A future version may add a pluggable `stateStore` adapter for multi-instance
deployments. Open an issue if you need this.

### 3. `requiresReauth` is a signal, not an action

When a refresh fails with HTTP 400 or 401, `OAuthRefreshError.requiresReauth`
is `true`. This indicates the `refresh_token` has been revoked, expired, or
otherwise invalidated by the provider. **The toolkit does not auto-delete
your storage** — that decision belongs to the caller, who knows whether to
log first, retain rows for audit, or prompt the user immediately.

Typical handling:

```js
try {
  const token = await client.getValidAccessToken();
  // ...
} catch (err) {
  if (err instanceof OAuthRefreshError && err.requiresReauth) {
    // Surface a "Reconnect" UX to the user.
    // Optionally call client.disconnect() once you've recorded the event.
  }
}
```

`getValidAccessToken()` returns `null` (rather than throwing) on refresh
failure so application code can branch on a single null check; check
`getConnectionStatus()` for the detailed state.

## What this library does **not** do

- Doesn't know about specific providers (no `Atlassian`, `GitHub`, etc.). You
  bring URLs and scopes.
- Doesn't render callback HTML or own your HTTP routing — your framework does.
- Doesn't fetch user profile / "account summary" data — provider-specific.
- Doesn't encrypt tokens — your storage adapter does.
- Doesn't auto-delete storage on auth failures — caller decides cleanup.

## License

MIT © 2026 Hamed Sattari
