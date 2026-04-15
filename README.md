# TimeFrontiers API Auth Client

Client-side API authentication and request signing for TimeFrontiers APIs.

[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.1-8892BF.svg)](https://php.net/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Installation

```bash
composer require timefrontiers/api-auth-client
```

## Requirements

- PHP 8.1+
- ext-curl
- ext-json

## Quick Start

```php
<?php

use TimeFrontiers\Auth\Client\{Credentials, ApiClient};

// Create credentials
$credentials = new Credentials(
  app_id: '123',
  public_key: 'pk_abc123...',
  secret_key: 'sk_xyz789...'
);

// Create client
$client = new ApiClient($credentials, 'https://api.example.com');

// Make requests (automatically signed)
$response = $client->get('/users');
$response = $client->post('/users', ['name' => 'John', 'email' => 'john@example.com']);
```

## Credentials

### Direct Instantiation

```php
$credentials = new Credentials(
  app_id: '123',
  public_key: 'pk_abc123...',
  secret_key: 'sk_xyz789...'
);
```

### From Array

```php
$credentials = Credentials::fromArray([
  'app_id' => '123',
  'public_key' => 'pk_abc123...',
  'secret_key' => 'sk_xyz789...',
]);
```

### From Environment

```php
// Uses: API_APP_ID, API_PUBLIC_KEY, API_SECRET_KEY
$credentials = Credentials::fromEnv();

// Or with custom prefix
// Uses: MYAPP_APP_ID, MYAPP_PUBLIC_KEY, MYAPP_SECRET_KEY
$credentials = Credentials::fromEnv('MYAPP');
```

## API Client

### Basic Usage

```php
$client = new ApiClient($credentials, 'https://api.example.com');

// GET request
$response = $client->get('/users');

// GET with query parameters
$response = $client->get('/users', ['status' => 'active', 'limit' => 10]);

// POST request
$response = $client->post('/users', [
  'name' => 'John Doe',
  'email' => 'john@example.com',
]);

// PUT request
$response = $client->put('/users/123', ['name' => 'Jane Doe']);

// PATCH request
$response = $client->patch('/users/123', ['status' => 'inactive']);

// DELETE request
$response = $client->delete('/users/123');
```

### Configuration

```php
$client = new ApiClient(
  credentials: $credentials,
  base_url: 'https://api.example.com',
  timeout: 60,                          // seconds
  default_headers: ['Accept-Language' => 'en'],
  verify_ssl: true
);

// Create variations
$v2_client = $client->withBaseUrl('https://api.example.com/v2');
$custom_client = $client->withHeaders(['X-Custom' => 'value']);
```

### Response Handling

```php
$response = $client->get('/users/123');

// Status checks
$response->isSuccess();      // 2xx
$response->isError();        // 4xx or 5xx
$response->isClientError();  // 4xx
$response->isServerError();  // 5xx
$response->getStatusCode();  // e.g., 200

// Body access
$response->getBody();        // Raw string
$response->json();           // Parsed array
$response->get('data.user.name');  // Dot notation

// Headers
$response->getHeaders();
$response->getHeader('content-type');

// Error handling
try {
  $response->throwIfError();
} catch (ApiException $e) {
  echo $e->getMessage();
  echo $e->getErrorCode();
  echo $e->getStatusCode();
}
```

## Manual Signing

For advanced use cases or other HTTP libraries:

```php
use TimeFrontiers\Auth\Client\Signer;

// Generate headers
$headers = Signer::generateHeaders(
  $credentials,
  method: 'POST',
  path: '/api/v1/users',
  body: '{"name":"John"}'
);
// Returns:
// [
//   'X-App-Id' => '123',
//   'X-Timestamp' => '1699999999',
//   'X-Nonce' => 'a1b2c3d4...',
//   'X-Body-Hash' => 'abc123...',
//   'X-Signature' => 'xyz789...',
// ]

// Or formatted for cURL
$curl_headers = Signer::generateCurlHeaders($credentials, 'POST', '/api/v1/users', $body);
// Returns: ['X-App-Id: 123', 'X-Timestamp: 1699999999', ...]
```

## Signing Algorithm

The signing algorithm is language-agnostic. Here's how it works:

### Canonical String Format

```
{app_id}
{HTTP_METHOD}
{path}
{timestamp}
{nonce}
{body_hash}
```

Each component on its own line (newline-separated).

### Signature Generation

```
signature = HMAC-SHA256(secret_key, canonical_string) → hex-encoded
```

### Required Headers

| Header | Description |
|--------|-------------|
| `X-App-Id` | Application ID |
| `X-Timestamp` | Unix timestamp |
| `X-Nonce` | Unique random string (32+ chars) |
| `X-Body-Hash` | SHA-256 hash of body (if body present) |
| `X-Signature` | HMAC-SHA256 signature |

## Multi-Language Examples

### JavaScript

```javascript
const crypto = require('crypto');

function signRequest(credentials, method, path, body = '') {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('hex');
  const bodyHash = body ? crypto.createHash('sha256').update(body).digest('hex') : '';

  const canonical = [
    credentials.appId,
    method.toUpperCase(),
    path,
    timestamp,
    nonce,
    bodyHash
  ].join('\n');

  const signature = crypto
    .createHmac('sha256', credentials.secretKey)
    .update(canonical)
    .digest('hex');

  return {
    'X-App-Id': credentials.appId,
    'X-Timestamp': timestamp.toString(),
    'X-Nonce': nonce,
    'X-Body-Hash': bodyHash,
    'X-Signature': signature
  };
}
```

### Python

```python
import hmac
import hashlib
import time
import secrets

def sign_request(credentials, method, path, body=''):
    timestamp = int(time.time())
    nonce = secrets.token_hex(16)
    body_hash = hashlib.sha256(body.encode()).hexdigest() if body else ''

    canonical = '\n'.join([
        credentials['app_id'],
        method.upper(),
        path,
        str(timestamp),
        nonce,
        body_hash
    ])

    signature = hmac.new(
        credentials['secret_key'].encode(),
        canonical.encode(),
        hashlib.sha256
    ).hexdigest()

    return {
        'X-App-Id': credentials['app_id'],
        'X-Timestamp': str(timestamp),
        'X-Nonce': nonce,
        'X-Body-Hash': body_hash,
        'X-Signature': signature
    }
```

### Bash (cURL)

```bash
#!/bin/bash

APP_ID="123"
SECRET_KEY="sk_xyz789..."
METHOD="POST"
PATH="/api/v1/users"
BODY='{"name":"John"}'

TIMESTAMP=$(date +%s)
NONCE=$(openssl rand -hex 16)
BODY_HASH=$(echo -n "$BODY" | sha256sum | cut -d' ' -f1)

CANONICAL="${APP_ID}
${METHOD}
${PATH}
${TIMESTAMP}
${NONCE}
${BODY_HASH}"

SIGNATURE=$(echo -n "$CANONICAL" | openssl dgst -sha256 -hmac "$SECRET_KEY" | cut -d' ' -f2)

curl -X POST "https://api.example.com${PATH}" \
  -H "Content-Type: application/json" \
  -H "X-App-Id: ${APP_ID}" \
  -H "X-Timestamp: ${TIMESTAMP}" \
  -H "X-Nonce: ${NONCE}" \
  -H "X-Body-Hash: ${BODY_HASH}" \
  -H "X-Signature: ${SIGNATURE}" \
  -d "$BODY"
```

## Error Handling

```php
use TimeFrontiers\Auth\Client\ApiException;

try {
  $response = $client->post('/users', $data)->throwIfError();
  $user = $response->get('data');
} catch (ApiException $e) {
  // API returned an error
  echo "Error: " . $e->getMessage();
  echo "Code: " . $e->getErrorCode();
  echo "Status: " . $e->getStatusCode();

  // Access full response if needed
  $response = $e->getResponse();
}
```

## Security Notes

- **Credentials are immutable** — Cannot be modified after creation
- **Secret key is redacted** — Won't appear in `var_dump()` or logs
- **Credentials cannot be serialized** — Prevents accidental storage
- **Nonces are cryptographically random** — Uses `random_bytes()`
- **Constant-time comparison** — Signature verification uses `hash_equals()`

## License

MIT License
