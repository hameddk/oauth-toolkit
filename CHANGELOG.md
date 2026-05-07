# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-05-07

### Added
- Support for object-form `tokenUrl` with separate `exchange` and `refresh`
  endpoints (`{ exchange, refresh }`). Lets providers that split user-token
  exchange from the standard refresh grant be configured cleanly without
  custom fetch routing. The string form is unchanged and remains the
  recommended default — see "tokenUrl forms" in the README.
- URL validation for object-form `tokenUrl`: both endpoints are parsed at
  client construction, and an `OAuthConfigError` is thrown if either is
  malformed.

### Changed
- `provider.tokenUrl` JSDoc type widened from `string` to
  `string | { exchange: string, refresh: string }`. Backwards compatible —
  all existing callers continue to work without changes.

## [0.1.0] — 2026-05-07

### Added
- Initial release.
- Authorization Code flow with optional PKCE (S256).
- Token refresh with promise-coalescing.
- Pluggable storage adapter (caller controls persistence and encryption).
- In-memory state store with TTL + auto-cleanup.
- `requiresReauth` flag on refresh failures (no auto-deletion of storage).
- Lazy `clientId` / `clientSecret` resolvers (sync or async).
- Custom `parseTokenResponse` for non-standard provider responses.
- Zero dependencies, ESM, Node ≥ 18.

[0.2.0]: https://github.com/hameddk/oauth-toolkit/releases/tag/v0.2.0
[0.1.0]: https://github.com/hameddk/oauth-toolkit/releases/tag/v0.1.0
