/**
 * Shared test utilities. Not a test file.
 */

/** In-memory storage adapter. */
export function makeMemoryStorage(initial = {}) {
  const map = new Map(Object.entries(initial));
  const calls = { load: 0, save: 0, delete: 0 };
  return {
    calls,
    async load(provider) {
      calls.load++;
      return map.get(provider) ?? null;
    },
    async save(provider, tokens) {
      calls.save++;
      map.set(provider, { ...tokens, updated_at: 1700000000 });
    },
    async delete(provider) {
      calls.delete++;
      map.delete(provider);
    },
    _peek(provider) {
      return map.get(provider) ?? null;
    },
    _setRaw(provider, tokens) {
      map.set(provider, tokens);
    },
  };
}

/**
 * Build a fake fetch that returns scripted responses. Each call dequeues one.
 * Each entry is either:
 *   { status, body }              // body is JSON-serialized object or string
 *   { throws: Error }             // network error simulation
 *   (req) => Response | throws    // function form
 *
 * Returns { fetch, calls } where calls is an array of {url, options}.
 */
export function makeScriptedFetch(script) {
  const queue = [...script];
  const calls = [];
  async function fetchImpl(url, options) {
    calls.push({ url, options });
    const next = queue.shift();
    if (!next) {
      throw new Error(`scripted fetch exhausted at call #${calls.length} (${url})`);
    }
    if (typeof next === 'function') {
      return next({ url, options });
    }
    if (next.throws) throw next.throws;
    const bodyText = typeof next.body === 'string' ? next.body : JSON.stringify(next.body);
    return makeResponse(next.status ?? 200, bodyText);
  }
  return { fetch: fetchImpl, calls, queue };
}

function makeResponse(status, bodyText) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async text() {
      return bodyText;
    },
  };
}

/** Build a controllable clock. `setSec(n)` jumps absolute Unix seconds. */
export function makeClock(initialSec = 1_700_000_000) {
  let ms = initialSec * 1000;
  return {
    now: () => ms,
    setSec(sec) {
      ms = sec * 1000;
    },
    setMs(value) {
      ms = value;
    },
    advanceSec(sec) {
      ms += sec * 1000;
    },
    advanceMs(value) {
      ms += value;
    },
    nowSec() {
      return Math.floor(ms / 1000);
    },
  };
}

/** Minimal "acme" provider config used across tests. */
export function acmeProvider(overrides = {}) {
  return {
    name: 'acme',
    authorizationUrl: 'https://auth.acme.example/oauth/authorize',
    tokenUrl: 'https://auth.acme.example/oauth/token',
    scopes: ['read', 'write'],
    ...overrides,
  };
}
