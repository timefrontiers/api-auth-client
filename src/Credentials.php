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

  /**
   * Create credentials from snake_case or camelCase keys.
   *
   * @param array<string, mixed> $data
   */
  public static function fromArray(#[\SensitiveParameter] array $data):self {
    return new self(
      self::_toString($data['app_id'] ?? $data['appId'] ?? '', 'Application ID'),
      self::_toString($data['public_key'] ?? $data['publicKey'] ?? '', 'Public key selector'),
      self::_toString($data['secret_key'] ?? $data['secretKey'] ?? '', 'Secret key')
    );
  }

  /**
   * Create credentials from {PREFIX}_APP_ID, _PUBLIC_KEY, and _SECRET_KEY.
   */
  public static function fromEnv(string $prefix = 'API'):self {
    $prefix = \rtrim($prefix, '_');
    if ($prefix === '' || !\preg_match('/\A[A-Za-z][A-Za-z0-9_]*\z/D', $prefix)) {
      throw new \InvalidArgumentException('Environment prefix must be a valid identifier.');
    }

    $app_id = self::_environmentValue("{$prefix}_APP_ID");
    $public_key = self::_environmentValue("{$prefix}_PUBLIC_KEY");
    $secret_key = self::_environmentValue("{$prefix}_SECRET_KEY");

    return new self($app_id, $public_key, $secret_key);
  }

  public function getAppId():string {
    return $this->_app_id;
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
   * @return array{app_id: string, public_key: string, secret_key: string}
   */
  public function __debugInfo():array {
    return [
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

  private static function _environmentValue(string $name):string {
    $value = \getenv($name);
    if ($value !== false) {
      return $value;
    }

    if (!\defined($name)) {
      return '';
    }

    return self::_toString(\constant($name), $name);
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
