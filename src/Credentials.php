<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client;

/**
 * Immutable API credentials.
 *
 * The public key is a key selector, not an asymmetric key and not a secret.
 */
final class Credentials {

  private const MAX_IDENTIFIER_LENGTH = 128;
  private const MAX_SECRET_LENGTH = 4096;

  private string $_app_id;
  private string $_public_key;
  private string $_secret_key;
  private bool $_uses_legacy_app_id = true;

  /**
   * Legacy constructor retained for v1.0 compatibility.
   *
   * The app_id argument is always transmitted as X-App-Id. New integrations
   * should use forSelector() so numeric public selectors remain public names.
   */
  public function __construct(
    string $app_id,
    string $public_key,
    #[\SensitiveParameter]
    string $secret_key
  ) {
    self::_assertIdentifier($app_id, 'Application ID');
    self::_assertIdentifier($public_key, 'Public key selector');

    if ($secret_key === '' || \strlen($secret_key) > self::MAX_SECRET_LENGTH) {
      throw new \InvalidArgumentException('Secret key must have a valid length.');
    }

    $this->_app_id = $app_id;
    $this->_public_key = $public_key;
    $this->_secret_key = $secret_key;
  }

  public static function forSelector(
    string $credential_selector,
    string $public_key,
    #[\SensitiveParameter]
    string $secret_key
  ):self {
    self::_assertCredentialSelector($credential_selector);
    $credentials = new self($credential_selector, $public_key, $secret_key);
    $credentials->_uses_legacy_app_id = false;
    return $credentials;
  }

  public static function forLegacyAppId(
    string $app_id,
    string $public_key,
    #[\SensitiveParameter]
    string $secret_key
  ):self {
    self::_assertLegacyAppId($app_id);
    return new self($app_id, $public_key, $secret_key);
  }

  /**
   * Create credentials from snake_case or camelCase keys.
   *
   * @param array<string, mixed> $data
   */
  public static function fromArray(#[\SensitiveParameter] array $data):self {
    $public_key = self::_toString($data['public_key'] ?? $data['publicKey'] ?? '', 'Public key selector');
    $secret_key = self::_toString($data['secret_key'] ?? $data['secretKey'] ?? '', 'Secret key');

    if (\array_key_exists('credential_selector', $data) || \array_key_exists('credentialSelector', $data)) {
      return self::forSelector(
        self::_toString(
          $data['credential_selector'] ?? $data['credentialSelector'] ?? null,
          'Application credential selector'
        ),
        $public_key,
        $secret_key
      );
    }

    return self::forLegacyAppId(
      self::_toString($data['app_id'] ?? $data['appId'] ?? '', 'Legacy application ID'),
      $public_key,
      $secret_key
    );
  }

  /**
   * Create credentials from {PREFIX}_CREDENTIAL_SELECTOR (or legacy _APP_ID),
   * _PUBLIC_KEY, and _SECRET_KEY.
   */
  public static function fromEnv(string $prefix = 'API'):self {
    $prefix = \rtrim($prefix, '_');
    if ($prefix === '' || !\preg_match('/\A[A-Za-z][A-Za-z0-9_]*\z/D', $prefix)) {
      throw new \InvalidArgumentException('Environment prefix must be a valid identifier.');
    }

    $credential_selector = self::_environmentValueOrNull("{$prefix}_CREDENTIAL_SELECTOR");
    $public_key = self::_environmentValue("{$prefix}_PUBLIC_KEY");
    $secret_key = self::_environmentValue("{$prefix}_SECRET_KEY");

    if ($credential_selector !== null) {
      return self::forSelector($credential_selector, $public_key, $secret_key);
    }

    return self::forLegacyAppId(
      self::_environmentValue("{$prefix}_APP_ID"),
      $public_key,
      $secret_key
    );
  }

  public function getAppId():string {
    return $this->_app_id;
  }

  /** Stable public credential selector used by the current protocol. */
  public function getCredentialSelector():string {
    return $this->_app_id;
  }

  /** X-App-Id is retained only for explicitly selected migration compatibility. */
  public function usesLegacyAppId():bool {
    return $this->_uses_legacy_app_id;
  }

  /** @deprecated Use usesLegacyAppId(). */
  public function usesLegacyNumericAppId():bool {
    return $this->usesLegacyAppId();
  }

  public function getPublicKey():string {
    return $this->_public_key;
  }

  /**
   * Return the HMAC secret. Do not log or serialize this value.
   */
  public function getSecretKey():string {
    return $this->_secret_key;
  }

  /**
   * @return array{credential_type: string, app_id: string, public_key: string, secret_key: string}
   */
  public function __debugInfo():array {
    return [
      'credential_type' => $this->_uses_legacy_app_id ? 'legacy_app_id' : 'public_selector',
      'app_id' => $this->_app_id,
      'public_key' => $this->_public_key,
      'secret_key' => '[REDACTED]',
    ];
  }

  /**
   * @return never
   */
  public function __serialize():array {
    throw new \RuntimeException('Credentials cannot be serialized for security reasons.');
  }

  /**
   * @param array<array-key, mixed> $data
   * @return never
   */
  public function __unserialize(#[\SensitiveParameter] array $data):void {
    throw new \RuntimeException('Credentials cannot be unserialized for security reasons.');
  }

  private static function _assertIdentifier(string $value, string $label):void {
    if (
      $value === ''
      || \strlen($value) > self::MAX_IDENTIFIER_LENGTH
      || !\preg_match('/\A[\x21-\x7E]+\z/D', $value)
    ) {
      throw new \InvalidArgumentException("{$label} must be a bounded printable identifier.");
    }
  }

  private static function _assertLegacyAppId(string $app_id):void {
    if (
      !\preg_match('/\A[1-9][0-9]{0,18}\z/D', $app_id)
      || (int) $app_id <= 0
      || (string) (int) $app_id !== $app_id
    ) {
      throw new \InvalidArgumentException('Legacy application ID must be a canonical positive integer.');
    }
  }

  private static function _assertCredentialSelector(string $credential_selector):void {
    if (!\preg_match('/\A[a-z0-9][a-z0-9._-]{0,127}\z/D', $credential_selector)) {
      throw new \InvalidArgumentException('Application credential selector is invalid.');
    }
  }

  private static function _environmentValue(string $name):string {
    return self::_environmentValueOrNull($name) ?? '';
  }

  private static function _environmentValueOrNull(string $name):?string {
    $value = \getenv($name);
    if ($value !== false) {
      return $value;
    }

    return \defined($name) ? self::_toString(\constant($name), $name) : null;
  }

  private static function _toString(mixed $value, string $label):string {
    if (\is_string($value)) {
      return $value;
    }

    if (\is_int($value) || \is_float($value)) {
      return (string) $value;
    }

    throw new \InvalidArgumentException("{$label} must be a string or number.");
  }
}
