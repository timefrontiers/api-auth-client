# Upgrading to 1.1

Version 1.1 is a compatible protocol-hardening release paired with
`timefrontiers/api-auth:^1.1`. The canonical HMAC string remains the six-line
1.0 format, so a 1.1 server can retain a documented migration window for 1.0
clients.

## Runtime and installation

PHP 8.5 or later is required:

```bash
composer require timefrontiers/api-auth-client:^1.1
```

## Required configuration changes

1. Remove `verify_ssl: false`. TLS peer and host verification cannot be
   disabled. For local loopback development only, opt in with
   `allow_http_for_local_development: true`.
2. Remove any authentication headers from default or request header arrays.
   The client owns `X-App-Id`, `X-Public-Key`, `X-Timestamp`, `X-Nonce`,
   `X-Body-Hash`, and `X-Signature`.
3. Ensure paths are origin-form targets beginning with `/`. Do not pass an
   absolute URL, `//host` target, fragment, raw space, or control character.
4. Treat 3xx responses as errors. Redirect following is disabled to prevent
   credential forwarding.
5. If response code depended on `toArray()['body']` or `['headers']`, move to
   the explicit `getBody()` or header accessors and keep those values out of
   logs.
6. Keep connect and total timeouts within `0 < timeout <= 86400` seconds.

The fifth constructor argument, `verify_ssl`, is retained so existing secure
calls using `true` continue to work. It will not permit an insecure setting.

## Exact bytes now define the request

The body `"0"` is now sent, hashed, and signed. Only the empty string omits the
body hash. If a workaround previously replaced `"0"` or skipped such a body,
remove it.

`get()` now encodes array queries using RFC 3986, recursively sorts associative
keys, and preserves list order. Spaces are `%20`, not `+`. Manual query strings
passed in the request target remain byte-for-byte unchanged.

JSON map keys are recursively sorted, list order is retained, and the flags are
`JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE |
JSON_PRESERVE_ZERO_FRACTION`. Invalid UTF-8, recursion, unsupported values, or
non-finite numbers throw `ClientConfigurationException` with
`JSON_ENCODING_ERROR` before any I/O.

A base URL path is now part of the signed target. For example,
`https://api.example.com/v1` plus `/users` signs `/v1/users`. This fixes the 1.0
case where the signed path could differ from the wire target.

The cURL transport now supplies the canonical request-target explicitly and
uses path-as-is handling. Dot segments such as `/a/../b` and lowercase percent
escapes therefore remain exactly as signed on the physical request line.

## Public key selector

1.1 sends `X-Public-Key` from `Credentials`. The paired server uses it as an
optional selector/app cross-check. It is not added to the canonical string and
must remain optional for 1.0 clients during the migration window.

## Response changes

- `isError()` and `throwIfError()` now cover every non-2xx status.
- `getHeaderValues()` and `getHeadersMulti()` expose repeated response fields;
  `getHeader()` and `getHeaders()` retain combined string convenience values.
- `hasJsonError()`, `getJsonError()`, and `isJsonScalar()` distinguish malformed
  JSON, valid scalar JSON, and an empty body while `json()` remains `?array`.
- Remote error fields are bounded and type-normalized. Oversized or malformed
  error bodies produce `HTTP {status}` and `API_ERROR`.
- `toArray()` is safe metadata only. Raw bodies and response headers may contain
  credentials or personal data and require explicit access.

## Custom transports

The default remains cURL. A test or host can inject `HttpTransportInterface`.
One `send()` call represents one physical attempt. A transport must honor the
immutable request's TLS, redirect, protocol, and timeout policy and must never
retry a signed request without a newly generated timestamp and nonce.

## Coordinated rollout

1. Run this package's shared vectors from `fixtures/protocol-v1.1.json`.
2. Upgrade and release `timefrontiers/api-auth:^1.1` against the same committed
   fixture, including optional public-key cross-checking and exact `"0"` body
   handling.
3. During the documented migration window, confirm the 1.1 server still
   accepts a 1.0 client without `X-Public-Key`.
4. Deploy the verifier before requiring the selector header operationally.
