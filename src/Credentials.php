<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client;

/**
 * Immutable value object holding API credentials.
 *
 * Use this to securely store and pass around your API credentials
 * without risk of accidental modification.
 */
final class Credentials {

  private string $_app_id;
  private string $_public_key;
  private string $_secret_key;

  public function __construct(string $app_id, string $public_key, string $secret_key) {
    if (empty($app_id) || empty($public_key) || empty($secret_key)) {
      throw new \InvalidArgumentException('All credential fields are required');
    }

    $this->_app_id = $app_id;
    $this->_public_key = $public_key;
    $this->_secret_key = $secret_key;
  }

  /**
   * Create from an associative array.
   */
  public static function fromArray(array $data):self {
    return new self(
      (string) ($data['app_id'] ?? $data['appId'] ?? ''),
      (string) ($data['public_key'] ?? $data['publicKey'] ?? ''),
      (string) ($data['secret_key'] ?? $data['secretKey'] ?? '')
    );
  }

  /**
   * Create from environment variables.
   *
   * Looks for: API_APP_ID, API_PUBLIC_KEY, API_SECRET_KEY
   * Or with custom prefix: {PREFIX}_APP_ID, etc.
   */
  public static function fromEnv(string $prefix = 'API'):self {
    $prefix = \rtrim($prefix, '_');

    $app_id = \getenv("{$prefix}_APP_ID") ?: '';
    $public_key = \getenv("{$prefix}_PUBLIC_KEY") ?: '';
    $secret_key = \getenv("{$prefix}_SECRET_KEY") ?: '';

    // Also check for defined constants
    if (empty($app_id) && \defined("{$prefix}_APP_ID")) {
      $app_id = \constant("{$prefix}_APP_ID");
    }
    if (empty($public_key) && \defined("{$prefix}_PUBLIC_KEY")) {
      $public_key = \constant("{$prefix}_PUBLIC_KEY");
    }
    if (empty($secret_key) && \defined("{$prefix}_SECRET_KEY")) {
      $secret_key = \constant("{$prefix}_SECRET_KEY");
    }

    return new self($app_id, $public_key, $secret_key);
  }

  public function getAppId():string {
    return $this->_app_id;
  }

  public function getPublicKey():string {
    return $this->_public_key;
  }

  public function getSecretKey():string {
    return $this->_secret_key;
  }

  /**
   * Prevent secret key from appearing in var_dump/print_r.
   */
  public function __debugInfo():array {
    return [
      'app_id' => $this->_app_id,
      'public_key' => $this->_public_key,
      'secret_key' => '[REDACTED]',
    ];
  }

  /**
   * Prevent serialization of credentials.
   */
  public function __serialize():array {
    throw new \RuntimeException('Credentials cannot be serialized for security reasons');
  }

  public function __unserialize(array $data):void {
    throw new \RuntimeException('Credentials cannot be unserialized for security reasons');
  }
}
