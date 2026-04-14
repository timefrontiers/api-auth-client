# TimeFrontiers API Auth Client

Official client library for signing TimeFrontiers API requests.

## Installation

```bash
composer require tymfrontiers/api-auth-client
```

## Quick Start

### 1. Get Your Credentials

Sign up at respetive platform to create an app and get your credentials:

- **App ID** — Your application identifier
- **Public Key** — Used to identify your app (`pk_...`)
- **Secret Key** — Used to sign requests (`sk_...`) — **keep this secret!**

### 2. Make Authenticated Requests

```php
<?php

use TimeFrontiers\Auth\Client\{Credentials, ApiClient};

// Load credentials
$credentials = new Credentials(
  appId: 'your-app-id',
  publicKey: 'pk_your_public_key',
  secretKey: 'sk_your_secret_key'
);

// Create client
$client = new ApiClient($credentials, 'https://api.tymfrontiers.com');

// Make requests
$response = $client->get('/api/v1/users');
$response = $client->post('/api/v1/users', [
  'name' => 'John Doe',
  'email' => 'john@example.com'
]);

// Handle response
if ($response->isSuccess()) {
  $data = $response->json();
  print_r($data);
} else {
  echo "Error: " . $response->getStatusCode();
}
```

## Loading Credentials

### From Environment Variables

```php
// Reads _APP_ID, _PUBLIC_KEY, _SECRET_KEY
$credentials = Credentials::fromEnv();

// Or with custom env var names
$credentials = Credentials::fromEnv(
  appIdKey: 'MY_APP_ID',
  publicKeyKey: 'MY_PUBLIC_KEY',
  secretKeyKey: 'MY_SECRET_KEY'
);
```

### From Config Array

```php
$config = require 'config/tymfrontiers.php';
$credentials = Credentials::fromArray($config);
```

## Manual Signing (Advanced)

If you need to sign requests manually (e.g., with Guzzle):

```php
use TimeFrontiers\Auth\Client\{Credentials, Signer};

$credentials = new Credentials('app-id', 'pk_xxx', 'sk_xxx');

// For a GET request
$headers = Signer::generateHeaders($credentials, 'GET', '/api/v1/users');

// For a POST request with body
$body = json_encode(['name' => 'John']);
$headers = Signer::generateHeaders($credentials, 'POST', '/api/v1/users', $body);

// Headers are ready to use
// [
//   'X-App-Id' => 'app-id',
//   'X-Timestamp' => '1699900800',
//   'X-Nonce' => 'a1b2c3d4...',
//   'X-Body-Hash' => 'e3b0c442...',  (only if body present)
//   'X-Signature' => '7a8b9c0d...'
// ]
```

### With Guzzle

```php
use GuzzleHttp\Client;
use TimeFrontiers\Auth\Client\{Credentials, Signer};

$credentials = new Credentials('app-id', 'pk_xxx', 'sk_xxx');
$guzzle = new Client(['base_uri' => 'https://api.tymfrontiers.com']);

$body = json_encode(['name' => 'John']);
$headers = Signer::generateHeaders($credentials, 'POST', '/api/v1/users', $body);

$response = $guzzle->post('/api/v1/users', [
  'headers' => array_merge($headers, ['Content-Type' => 'application/json']),
  'body' => $body,
]);
```

## Signing Algorithm

The algorithm is simple and can be implemented in any language:

### Step 1: Build Canonical String

Join these values with newlines (`\n`):

```
{app_id}
{HTTP_METHOD}
{path}
{timestamp}
{nonce}
{body_hash}
```

| Field | Description | Example |
|-------|-------------|---------|
| `app_id` | Your app ID | `my-app` |
| `HTTP_METHOD` | Uppercase method | `POST` |
| `path` | Request path (no query string) | `/api/v1/users` |
| `timestamp` | Unix timestamp (seconds) | `1699900800` |
| `nonce` | Random string (min 16 chars) | `a1b2c3d4e5f6g7h8` |
| `body_hash` | SHA-256 of body (empty if no body) | `e3b0c442...` |

### Step 2: Sign

```
signature = HMAC-SHA256(secret_key, canonical_string)
```

### Step 3: Send Headers

```
X-App-Id: {app_id}
X-Timestamp: {timestamp}
X-Nonce: {nonce}
X-Body-Hash: {body_hash}  (only if body present)
X-Signature: {signature}
```

## Other Languages

### JavaScript / Node.js

```javascript
const crypto = require('crypto');

function sign(appId, secretKey, method, path, body = '') {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('hex');
  const bodyHash = body ? crypto.createHash('sha256').update(body).digest('hex') : '';
  
  const canonical = [appId, method.toUpperCase(), path, timestamp, nonce, bodyHash].join('\n');
  const signature = crypto.createHmac('sha256', secretKey).update(canonical).digest('hex');
  
  return {
    'X-App-Id': appId,
    'X-Timestamp': String(timestamp),
    'X-Nonce': nonce,
    'X-Body-Hash': bodyHash || undefined,
    'X-Signature': signature
  };
}
```

### Python

```python
import hmac, hashlib, secrets, time

def sign(app_id, secret_key, method, path, body=''):
    timestamp = int(time.time())
    nonce = secrets.token_hex(16)
    body_hash = hashlib.sha256(body.encode()).hexdigest() if body else ''
    
    canonical = '\n'.join([app_id, method.upper(), path, str(timestamp), nonce, body_hash])
    signature = hmac.new(secret_key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    
    return {
        'X-App-Id': app_id,
        'X-Timestamp': str(timestamp),
        'X-Nonce': nonce,
        'X-Body-Hash': body_hash or None,
        'X-Signature': signature
    }
```

### cURL / Bash

```bash
APP_ID="your-app-id"
SECRET_KEY="sk_your_secret_key"
TIMESTAMP=$(date +%s)
NONCE=$(openssl rand -hex 16)
BODY='{"name":"John"}'
BODY_HASH=$(echo -n "$BODY" | openssl dgst -sha256 | awk '{print $2}')

CANONICAL="$APP_ID
POST
/api/v1/users
$TIMESTAMP
$NONCE
$BODY_HASH"

SIGNATURE=$(echo -n "$CANONICAL" | openssl dgst -sha256 -hmac "$SECRET_KEY" | awk '{print $2}')

curl -X POST "https://api.tymfrontiers.com/api/v1/users" \
  -H "X-App-Id: $APP_ID" \
  -H "X-Timestamp: $TIMESTAMP" \
  -H "X-Nonce: $NONCE" \
  -H "X-Body-Hash: $BODY_HASH" \
  -H "X-Signature: $SIGNATURE" \
  -H "Content-Type: application/json" \
  -d "$BODY"
```

## Error Handling

```php
$response = $client->post('/api/v1/users', $data);

if ($response->isError()) {
  $error = $response->json();
  
  switch ($error['code'] ?? '') {
    case 'INVALID_SIGNATURE':
      // Check your secret key
      break;
    case 'REQUEST_EXPIRED':
      // Sync your clock, retry
      break;
    case 'REPLAY_DETECTED':
      // Duplicate nonce, retry with new nonce
      break;
    case 'RATE_LIMIT_EXCEEDED':
      // Wait and retry
      break;
  }
}

// Or throw on error
$response->throwIfError();
$data = $response->json();
```

## License

MIT
