# TimeFrontiers API Auth Client

Client-side HMAC request authentication for TimeFrontiers APIs.

[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.5-8892BF.svg)](https://php.net/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Installation

```bash
composer require timefrontiers/api-auth-client:^1.1
```

Requirements: PHP 8.5+, ext-curl, and ext-json.

## Quick start

```php
use TimeFrontiers\Auth\Client\{ApiClient, Credentials};

$credentials = new Credentials(
  app_id: '123',
  public_key: 'key-selector-2026-01',
  secret_key: $secretFromASecretManager
);

$client = new ApiClient($credentials, 'https://api.example.com');

$response = $client->get('/users', ['status' => 'active', 'limit' => 10]);
$response = $client->post('/users', ['name' => 'John', 'email' => 'john@example.com']);
```

`public_key` is a key selector used by a 1.1 server to cross-check the app and
credential record. It is not an asymmetric public key, is not a second secret,
and is not included in the six canonical lines.

Credentials can also be loaded with `Credentials::fromArray()` or
`Credentials::fromEnv('API')`. The latter reads `API_APP_ID`,
`API_PUBLIC_KEY`, and `API_SECRET_KEY`. Credential objects redact the HMAC
secret from debug output and cannot be serialized.

## Client configuration

```php
use TimeFrontiers\Auth\Client\{ApiClient, CurlTransport};

$client = new ApiClient(
  credentials: $credentials,
  base_url: 'https://api.example.com/v1',
  timeout: 30,
  default_headers: ['Accept-Language' => 'en'],
  verify_ssl: true,
  transport: new CurlTransport(),
  connect_timeout: 10
);
```

- HTTPS is required. TLS peer and host verification cannot be disabled.
- Redirects are not followed, so credentials are never forwarded implicitly.
- cURL is restricted to HTTPS and performs no automatic retries.
- Positive finite connect and total timeouts up to 86,400 seconds are required;
  sub-millisecond values safely round up to one millisecond.
- HTTP can only be enabled for `localhost`, `127.0.0.1`, or `::1` with the
  explicit `allow_http_for_local_development: true` constructor option.
- Base URLs may contain a path. That path becomes part of the exact signed
  request-target: base `https://api.example.com/v1` plus `/users` signs and
  sends `/v1/users`.

The `verify_ssl` argument remains for source compatibility with 1.0 callers,
but passing `false` now throws. Remove any insecure override before upgrading.

Use `withBaseUrl()` and `withHeaders()` to create configured copies. Defaults
and per-request headers are compared case-insensitively. `X-App-Id`,
`X-Public-Key`, `X-Timestamp`, `X-Nonce`, `X-Body-Hash`, and `X-Signature` are
reserved and cannot be supplied by callers.

## Request construction

The convenience methods are `get()`, `post()`, `put()`, `patch()`, and
`delete()`. `request()` accepts an exact string body and an already-built
origin-form target:

```php
$response = $client->request(
  method: 'POST',
  path: '/events?source=manual%20client',
  body: '0',
  headers: ['Content-Type' => 'text/plain']
);
```

The path must begin with one `/`. Absolute URLs, network-path targets beginning
with `//`, fragments, spaces, controls, and targets over 8192 bytes are
rejected. A manually built query is transmitted without parsing or re-encoding.
The default transport sets both cURL's explicit request-target and path-as-is
controls so dot segments and percent-escape casing remain byte-for-byte intact.

Array queries use RFC 3986 (`%20`, never `+`). Associative keys are sorted at
every level and list order is retained. PHP bracket notation represents nested
and repeated values:

```php
$client->get('/search', [
  'sort' => ['direction' => 'asc', 'by' => 'name'],
  'filter' => ['tags' => ['red', 'blue']],
]);

// /search?filter%5Btags%5D%5B0%5D=red
//   &filter%5Btags%5D%5B1%5D=blue
//   &sort%5Bby%5D=name&sort%5Bdirection%5D=asc
```

JSON bodies recursively sort associative keys and preserve list order. The
exact encoding flags are `JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES |
JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION`. Encoding failure throws
`ClientConfigurationException` with code `JSON_ENCODING_ERROR` before a
transport is opened.

## Signing protocol

The canonical string remains the 1.0 six-line format:

```text
app_id
UPPERCASE_METHOD
origin-form request-target
positive Unix timestamp
32-character lowercase hexadecimal nonce
body_hash
```

`body_hash` is lowercase SHA-256 hexadecimal for every non-empty byte string.
The body `"0"` is non-empty and is hashed. Only `''` leaves the final canonical
line empty and omits `X-Body-Hash`.

```php
use TimeFrontiers\Auth\Client\Signer;

$headers = Signer::generateHeaders(
  $credentials,
  method: 'POST',
  path: '/api/v1/users?notify=true',
  body: '{"name":"John"}'
);
```

A new timestamp and nonce are generated for each physical request. Version 1.1
does not retry. A future retry implementation must re-sign every attempt and
limit retries to explicitly retry-safe operations.

Deterministic shared vectors, including empty and `"0"` bodies, UTF-8 JSON,
RFC 3986 spaces, nested/repeated queries, and an invalid signature, live in
[`fixtures/protocol-v1.1.json`](fixtures/protocol-v1.1.json). The paired
`timefrontiers/api-auth` 1.1 verifier must consume this committed fixture.

### JavaScript signing

```javascript
const crypto = require('crypto');

function signRequest(credentials, method, requestTarget, body = '') {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('hex');
  const bodyHash = body !== ''
    ? crypto.createHash('sha256').update(body, 'utf8').digest('hex')
    : '';

  const canonical = [
    credentials.appId,
    method.toUpperCase(),
    requestTarget,
    String(timestamp),
    nonce,
    bodyHash
  ].join('\n');

  return {
    'X-App-Id': credentials.appId,
    'X-Public-Key': credentials.publicKey,
    'X-Timestamp': String(timestamp),
    'X-Nonce': nonce,
    ...(bodyHash !== '' ? {'X-Body-Hash': bodyHash} : {}),
    'X-Signature': crypto
      .createHmac('sha256', credentials.secretKey)
      .update(canonical, 'utf8')
      .digest('hex')
  };
}
```

### Python signing

```python
import hashlib
import hmac
import secrets
import time

def sign_request(credentials, method, request_target, body=''):
    timestamp = int(time.time())
    nonce = secrets.token_hex(16)
    body_hash = hashlib.sha256(body.encode('utf-8')).hexdigest() if body != '' else ''
    canonical = '\n'.join([
        credentials['app_id'], method.upper(), request_target,
        str(timestamp), nonce, body_hash
    ])

    headers = {
        'X-App-Id': credentials['app_id'],
        'X-Public-Key': credentials['public_key'],
        'X-Timestamp': str(timestamp),
        'X-Nonce': nonce,
        'X-Signature': hmac.new(
            credentials['secret_key'].encode('utf-8'),
            canonical.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    }
    if body_hash != '':
        headers['X-Body-Hash'] = body_hash
    return headers
```

### Bash/cURL signing

```bash
APP_ID='123'
PUBLIC_KEY='key-selector-2026-01'
SECRET_KEY='read-this-from-a-secret-manager'
METHOD='POST'
REQUEST_TARGET='/api/v1/users'
BODY='0'
TIMESTAMP="$(date +%s)"
NONCE="$(openssl rand -hex 16)"

if [ -n "$BODY" ]; then
  BODY_HASH="$(printf '%s' "$BODY" | sha256sum | cut -d' ' -f1)"
  BODY_HASH_HEADER=(-H "X-Body-Hash: ${BODY_HASH}")
else
  BODY_HASH=''
  BODY_HASH_HEADER=()
fi

CANONICAL="${APP_ID}
${METHOD}
${REQUEST_TARGET}
${TIMESTAMP}
${NONCE}
${BODY_HASH}"
SIGNATURE="$(printf '%s' "$CANONICAL" | openssl dgst -sha256 -hmac "$SECRET_KEY" | awk '{print $2}')"

curl --proto '=https' --max-redirs 0 -X "$METHOD" "https://api.example.com${REQUEST_TARGET}" \
  -H "X-App-Id: ${APP_ID}" \
  -H "X-Public-Key: ${PUBLIC_KEY}" \
  -H "X-Timestamp: ${TIMESTAMP}" \
  -H "X-Nonce: ${NONCE}" \
  "${BODY_HASH_HEADER[@]}" \
  -H "X-Signature: ${SIGNATURE}" \
  --data-binary "$BODY"
```

## Injectable transport

`ApiClient` uses `CurlTransport` by default. Tests and host applications may
inject `HttpTransportInterface`. A transport receives one immutable
`HttpRequest` containing the final URL, exact target, exact body, normalized
headers, timeouts, TLS verification policy, redirect policy, and protocol
allowlist. It returns `ApiResponse` or throws `ApiException` for a transport
failure. Implementations must not log request headers or bodies and must not
retry automatically.

## Responses and errors

```php
$response = $client->get('/users/123');

$response->isSuccess();
$response->isError();                 // every non-2xx, including 3xx
$response->getStatusCode();
$response->json();                    // object/array or null
$response->hasJsonError();
$response->isJsonScalar();
$response->get('data.user.name');
$response->getHeader('content-type');
$response->getHeaderValues('set-cookie');
$response->throwIfError();
```

Malformed and scalar JSON are separately observable without changing the
backward-compatible `json(): ?array` return. Repeated response headers are
retained. Remote error message/code fields are type-normalized and bounded;
large or malformed error bodies produce a generic HTTP error rather than being
copied into an exception.

`getBody()`, `getHeadersMulti()`, and `getHeaderValues()` are explicit raw
accessors. Their values may contain secrets or personal data and must not be
logged. `toArray()` intentionally returns safe metadata only.

## Development

```bash
composer validate --strict --no-check-publish
composer check
composer audit --locked
```

The CI gate runs PHP 8.5 with both highest and lowest supported dependencies.

## License

MIT License.
