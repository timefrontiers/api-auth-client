# Changelog

All notable changes to this package are documented here.

## 1.1.1 - 2026-09-01

### Security

- Send explicit public application selectors in `X-App-Selector`, including
  numeric names, keeping database IDs out of newly provisioned credentials.
- Reserve both selector headers and ensure the selected wire value remains the
  first canonical HMAC line.

### Compatibility

- Add `Credentials::forSelector()` and `Credentials::forLegacyAppId()` so the
  chosen protocol is explicit rather than inferred from a numeric value.
- Validate public selectors against the same lowercase grammar enforced by the
  paired server.
- The legacy constructor, `app_id` array key, and `*_APP_ID` environment input
  continue to use `X-App-Id` during the documented migration window.

## 1.1.0 - 2026-08-20

### Required action

- PHP 8.5 is now the minimum supported runtime.
- HTTPS is required by default. `verify_ssl: false` now throws; HTTP is limited
  to explicitly enabled loopback development.
- Callers may no longer set authentication headers through default or
  per-request headers.
- All non-2xx responses, including redirects, are errors.

### Fixed

- Hash and send the non-empty body `"0"` instead of treating it as empty.
- Sign the exact final origin-form target, including a base URL path and the
  exact transmitted query bytes.
- Build array queries deterministically with RFC 3986 encoding and recursively
  sorted map keys.
- Encode deterministic UTF-8 JSON with exceptions before opening a transport.
- Preserve repeated fields from the final HTTP response header block.
- Normalize untrusted remote error fields without exposing an unbounded body.
- Preserve dot segments and percent-escape casing on the physical cURL request
  line with an explicit request target and path-as-is handling.
- Release cURL handles through PHP 8.5 object lifetime without calling the
  deprecated, no-op `curl_close()` function.
- Normalize bracketed IPv6 hosts without rejecting `::1` or rendering doubled
  brackets.
- Bound connect and total timeouts to a safely representable 86,400 seconds.

### Added

- Injectable `HttpTransportInterface`, immutable `HttpRequest`, and secure
  default `CurlTransport`.
- Optional `X-Public-Key` compatibility selector without changing the v1.0
  six-line canonical string.
- Shared cross-package protocol fixtures and comprehensive protocol, security,
  response, raw-wire loopback, and real transport success/failure tests.
- PHPStan level-max analysis and PHP 8.5 highest/lowest-dependency CI jobs.

### Security

- Reserve authentication headers case-insensitively and reject CR/LF header
  injection.
- Validate credential identifiers, methods, targets, timestamps, nonces,
  hashes, signatures, URLs, and timeouts.
- Keep TLS verification enabled, disable redirects, restrict cURL protocols,
  and omit request material from transport exceptions.
- Redact secret parameters and keep raw response data out of `toArray()`.
