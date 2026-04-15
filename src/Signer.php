<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client;

/**
 * Stateless request signer.
 *
 * This class handles all cryptographic operations for API authentication.
 * The signing algorithm is designed to be language-agnostic and can be
 * implemented in any language that supports HMAC-SHA256.
 *
 * Canonical String Format (newline-separated):
 *   {app_id}
 *   {HTTP_METHOD}
 *   {path}
 *   {timestamp}
 *   {nonce}
 *   {body_hash}
 *
 * Signature = HMAC-SHA256(secret_key, canonical_string) → hex-encoded
 */
final class Signer {

  // Header names
  public const HEADER_APP_ID = 'X-App-Id';
  public const HEADER_TIMESTAMP = 'X-Timestamp';
  public const HEADER_NONCE = 'X-Nonce';
  public const HEADER_BODY_HASH = 'X-Body-Hash';
  public const HEADER_SIGNATURE = 'X-Signature';

  // Defaults
  public const DEFAULT_NONCE_LENGTH = 32;

  /**
   * Generate all authentication headers for a request.
   *
   * @param Credentials $credentials API credentials
   * @param string $method HTTP method (GET, POST, etc.)
   * @param string $path Request path (e.g., /api/v1/users)
   * @param string $body Request body (empty string for GET)
   * @return array Associative array of headers
   */
  public static function generateHeaders(
    Credentials $credentials,
    string $method,
    string $path,
    string $body = ''
  ):array {
    $timestamp = \time();
    $nonce = self::generateNonce();
    $body_hash = !empty($body) ? self::hashBody($body) : '';

    $signature = self::sign(
      $credentials->getSecretKey(),
      $credentials->getAppId(),
      $method,
      $path,
      $timestamp,
      $nonce,
      $body_hash
    );

    $headers = [
      self::HEADER_APP_ID => $credentials->getAppId(),
      self::HEADER_TIMESTAMP => (string) $timestamp,
      self::HEADER_NONCE => $nonce,
      self::HEADER_SIGNATURE => $signature,
    ];

    if (!empty($body_hash)) {
      $headers[self::HEADER_BODY_HASH] = $body_hash;
    }

    return $headers;
  }

  /**
   * Generate headers formatted for cURL.
   *
   * @return array Indexed array of "Header: Value" strings
   */
  public static function generateCurlHeaders(
    Credentials $credentials,
    string $method,
    string $path,
    string $body = ''
  ):array {
    $headers = self::generateHeaders($credentials, $method, $path, $body);

    $curl_headers = [];
    foreach ($headers as $name => $value) {
      $curl_headers[] = "{$name}: {$value}";
    }

    return $curl_headers;
  }

  /**
   * Build the canonical string for signing.
   *
   * This is the string that gets signed with HMAC-SHA256.
   * The format is designed to be unambiguous and order-dependent.
   */
  public static function buildCanonicalString(
    string $app_id,
    string $method,
    string $path,
    int $timestamp,
    string $nonce,
    string $body_hash = ''
  ):string {
    return \implode("\n", [
      $app_id,
      \strtoupper($method),
      $path,
      (string) $timestamp,
      $nonce,
      $body_hash,
    ]);
  }

  /**
   * Sign a canonical string with the secret key.
   *
   * @return string Hex-encoded HMAC-SHA256 signature
   */
  public static function sign(
    string $secret_key,
    string $app_id,
    string $method,
    string $path,
    int $timestamp,
    string $nonce,
    string $body_hash = ''
  ):string {
    $canonical = self::buildCanonicalString(
      $app_id,
      $method,
      $path,
      $timestamp,
      $nonce,
      $body_hash
    );

    return \hash_hmac('sha256', $canonical, $secret_key);
  }

  /**
   * Generate a cryptographically secure nonce.
   */
  public static function generateNonce(int $length = self::DEFAULT_NONCE_LENGTH):string {
    return \bin2hex(\random_bytes((int) \ceil($length / 2)));
  }

  /**
   * Hash the request body.
   */
  public static function hashBody(string $body):string {
    return \hash('sha256', $body);
  }

  /**
   * Verify a signature (for testing/debugging).
   */
  public static function verifySignature(
    string $signature,
    string $secret_key,
    string $app_id,
    string $method,
    string $path,
    int $timestamp,
    string $nonce,
    string $body_hash = ''
  ):bool {
    $expected = self::sign(
      $secret_key,
      $app_id,
      $method,
      $path,
      $timestamp,
      $nonce,
      $body_hash
    );

    return \hash_equals($expected, $signature);
  }
}
