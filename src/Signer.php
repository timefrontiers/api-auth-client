<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client;

/**
 * Stateless signature generator.
 *
 * The signing algorithm is intentionally simple and well-documented
 * so it can be implemented in any programming language.
 *
 * == SIGNING ALGORITHM ==
 *
 * 1. Build the canonical string by joining these values with newlines (\n):
 *    - App ID
 *    - HTTP method (uppercase: GET, POST, PUT, DELETE, PATCH)
 *    - Request path (e.g., /api/v1/users) — no query string
 *    - Unix timestamp (seconds since epoch)
 *    - Nonce (random string, min 16 chars)
 *    - Body hash (SHA-256 of request body, or empty string if no body)
 *
 * 2. Compute HMAC-SHA256 of the canonical string using the secret key
 *
 * 3. Hex-encode the result
 *
 * == REQUIRED HEADERS ==
 *
 * X-App-Id: {app_id}
 * X-Timestamp: {unix_timestamp}
 * X-Nonce: {random_nonce}
 * X-Body-Hash: {sha256_of_body}  (omit or empty if no body)
 * X-Signature: {computed_signature}
 */
final class Signer
{
  public const ALGORITHM = 'sha256';
  public const HEADER_APP_ID = 'X-App-Id';
  public const HEADER_TIMESTAMP = 'X-Timestamp';
  public const HEADER_NONCE = 'X-Nonce';
  public const HEADER_BODY_HASH = 'X-Body-Hash';
  public const HEADER_SIGNATURE = 'X-Signature';

  /**
   * Generate a signature for a request.
   */
  public static function sign(
    Credentials $credentials,
    string $method,
    string $path,
    int $timestamp,
    string $nonce,
    string $bodyHash = ''
  ): string {
    $canonical = self::buildCanonicalString(
      $credentials->getAppId(),
      $method,
      $path,
      $timestamp,
      $nonce,
      $bodyHash
    );

    return \hash_hmac(self::ALGORITHM, $canonical, $credentials->getSecretKey());
  }

  /**
   * Generate all required headers for a request.
   *
   * This is a convenience method that generates the nonce and timestamp
   * automatically. Returns an associative array of headers.
   */
  public static function generateHeaders(
    Credentials $credentials,
    string $method,
    string $path,
    string $body = '',
    ?int $timestamp = null,
    ?string $nonce = null
  ): array {
    $timestamp = $timestamp ?? \time();
    $nonce = $nonce ?? self::generateNonce();
    $bodyHash = !empty($body) ? self::hashBody($body) : '';

    $signature = self::sign(
      $credentials,
      \strtoupper($method),
      $path,
      $timestamp,
      $nonce,
      $bodyHash
    );

    $headers = [
      self::HEADER_APP_ID => $credentials->getAppId(),
      self::HEADER_TIMESTAMP => (string) $timestamp,
      self::HEADER_NONCE => $nonce,
      self::HEADER_SIGNATURE => $signature,
    ];

    if (!empty($bodyHash)) {
      $headers[self::HEADER_BODY_HASH] = $bodyHash;
    }

    return $headers;
  }

  /**
   * Generate headers formatted for cURL.
   */
  public static function generateCurlHeaders(
    Credentials $credentials,
    string $method,
    string $path,
    string $body = ''
  ): array {
    $headers = self::generateHeaders($credentials, $method, $path, $body);

    return \array_map(
      fn($key, $value) => "{$key}: {$value}",
      \array_keys($headers),
      \array_values($headers)
    );
  }

  /**
   * Build the canonical string for signing.
   *
   * Public so other implementations can verify they're building it correctly.
   */
  public static function buildCanonicalString(
    string $appId,
    string $method,
    string $path,
    int $timestamp,
    string $nonce,
    string $bodyHash
  ): string {
    return \implode("\n", [
      $appId,
      \strtoupper($method),
      self::normalizePath($path),
      (string) $timestamp,
      $nonce,
      $bodyHash,
    ]);
  }

  /**
   * Hash the request body.
   */
  public static function hashBody(string $body): string
  {
    return \hash('sha256', $body);
  }

  /**
   * Generate a cryptographically secure nonce.
   */
  public static function generateNonce(int $length = 32): string
  {
    return \bin2hex(\random_bytes((int) \ceil($length / 2)));
  }

  /**
   * Normalize the path for consistent signing.
   *
   * - Removes query string
   * - Ensures leading slash
   * - Removes trailing slash (except for root)
   */
  public static function normalizePath(string $path): string
  {
    // Remove query string
    $path = \parse_url($path, PHP_URL_PATH) ?? $path;

    // Ensure leading slash
    if ($path === '' || $path[0] !== '/') {
      $path = '/' . $path;
    }

    // Remove trailing slash (except for root)
    if ($path !== '/' && \str_ends_with($path, '/')) {
      $path = \rtrim($path, '/');
    }

    return $path;
  }
}
