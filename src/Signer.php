<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client;

/**
 * Stateless HMAC-SHA256 request signer.
 *
 * The v1.1 line retains the six-line v1.0 canonical string:
 * app ID, uppercase method, origin-form request-target, timestamp, nonce,
 * and body hash.
 */
final class Signer {

  public const HEADER_APP_ID = 'X-App-Id';
  public const HEADER_PUBLIC_KEY = 'X-Public-Key';
  public const HEADER_TIMESTAMP = 'X-Timestamp';
  public const HEADER_NONCE = 'X-Nonce';
  public const HEADER_BODY_HASH = 'X-Body-Hash';
  public const HEADER_SIGNATURE = 'X-Signature';

  public const DEFAULT_NONCE_LENGTH = 32;
  public const MAX_REQUEST_TARGET_LENGTH = 8192;

  /**
   * Generate authentication headers for one physical request attempt.
   *
   * Timestamp and nonce overrides exist for deterministic protocol tests.
   * Production callers should omit them.
   *
   * @return array<string, string>
   */
  public static function generateHeaders(
    Credentials $credentials,
    string $method,
    string $path,
    string $body = '',
    ?int $timestamp = null,
    ?string $nonce = null
  ):array {
    $timestamp ??= \time();
    $nonce ??= self::generateNonce();
    $body_hash = $body !== '' ? self::hashBody($body) : '';

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
      self::HEADER_PUBLIC_KEY => $credentials->getPublicKey(),
      self::HEADER_TIMESTAMP => (string) $timestamp,
      self::HEADER_NONCE => $nonce,
      self::HEADER_SIGNATURE => $signature,
    ];

    if ($body_hash !== '') {
      $headers[self::HEADER_BODY_HASH] = $body_hash;
    }

    return $headers;
  }

  /**
   * @return list<string>
   */
  public static function generateCurlHeaders(
    Credentials $credentials,
    string $method,
    string $path,
    string $body = '',
    ?int $timestamp = null,
    ?string $nonce = null
  ):array {
    $headers = self::generateHeaders($credentials, $method, $path, $body, $timestamp, $nonce);
    $curl_headers = [];

    foreach ($headers as $name => $value) {
      self::_assertHeaderLine($name, $value);
      $curl_headers[] = "{$name}: {$value}";
    }

    return $curl_headers;
  }

  public static function buildCanonicalString(
    string $app_id,
    string $method,
    string $path,
    int $timestamp,
    string $nonce,
    string $body_hash = ''
  ):string {
    self::_assertIdentifier($app_id, 'Application ID');
    $method = self::normalizeMethod($method);
    self::validateRequestTarget($path);
    self::_assertTimestamp($timestamp);
    self::_assertNonce($nonce);
    self::_assertHash($body_hash, 'Body hash', true);

    return \implode("\n", [
      $app_id,
      $method,
      $path,
      (string) $timestamp,
      $nonce,
      $body_hash,
    ]);
  }

  public static function sign(
    #[\SensitiveParameter]
    string $secret_key,
    string $app_id,
    string $method,
    string $path,
    int $timestamp,
    string $nonce,
    string $body_hash = ''
  ):string {
    if ($secret_key === '') {
      throw new \InvalidArgumentException('Secret key is required.');
    }

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
   * Generate the protocol's exact 32-character lowercase hexadecimal nonce.
   */
  public static function generateNonce(int $length = self::DEFAULT_NONCE_LENGTH):string {
    if ($length !== self::DEFAULT_NONCE_LENGTH) {
      throw new \InvalidArgumentException('Nonce length must be exactly 32 hexadecimal characters.');
    }

    return \bin2hex(\random_bytes(self::DEFAULT_NONCE_LENGTH / 2));
  }

  public static function hashBody(string $body):string {
    return \hash('sha256', $body);
  }

  public static function verifySignature(
    string $signature,
    #[\SensitiveParameter]
    string $secret_key,
    string $app_id,
    string $method,
    string $path,
    int $timestamp,
    string $nonce,
    string $body_hash = ''
  ):bool {
    if (!\preg_match('/\A[a-f0-9]{64}\z/D', $signature)) {
      return false;
    }

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

  /** @return non-empty-string */
  public static function normalizeMethod(string $method):string {
    if ($method === '' || !\preg_match('/\A[!#$%&\'*+.^_`|~0-9A-Za-z-]+\z/D', $method)) {
      throw new \InvalidArgumentException('HTTP method must be a valid token.');
    }

    return \strtoupper($method);
  }

  public static function validateRequestTarget(string $request_target):void {
    if (
      $request_target === ''
      || !\str_starts_with($request_target, '/')
      || \str_starts_with($request_target, '//')
      || \strlen($request_target) > self::MAX_REQUEST_TARGET_LENGTH
      || \str_contains($request_target, '#')
      || \preg_match('/[\x00-\x20\x7F]/', $request_target)
    ) {
      throw new \InvalidArgumentException('Request target must be a valid bounded origin-form target.');
    }
  }

  private static function _assertIdentifier(string $value, string $label):void {
    if ($value === '' || \strlen($value) > 128 || !\preg_match('/\A[\x21-\x7E]+\z/D', $value)) {
      throw new \InvalidArgumentException("{$label} must be a bounded printable identifier.");
    }
  }

  private static function _assertTimestamp(int $timestamp):void {
    if ($timestamp <= 0) {
      throw new \InvalidArgumentException('Timestamp must be a positive Unix timestamp.');
    }
  }

  private static function _assertNonce(string $nonce):void {
    if (!\preg_match('/\A[a-f0-9]{32}\z/D', $nonce)) {
      throw new \InvalidArgumentException('Nonce must be exactly 32 lowercase hexadecimal characters.');
    }
  }

  private static function _assertHash(string $hash, string $label, bool $allow_empty):void {
    if (($allow_empty && $hash === '') || \preg_match('/\A[a-f0-9]{64}\z/D', $hash)) {
      return;
    }

    throw new \InvalidArgumentException("{$label} must be lowercase SHA-256 hexadecimal.");
  }

  private static function _assertHeaderLine(string $name, string $value):void {
    if (
      !\preg_match('/\A[!#$%&\'*+.^_`|~0-9A-Za-z-]+\z/D', $name)
      || \str_contains($value, "\r")
      || \str_contains($value, "\n")
    ) {
      throw new \InvalidArgumentException('Generated header is not safe to transmit.');
    }
  }
}
