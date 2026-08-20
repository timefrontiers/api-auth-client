<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client;

/**
 * Immutable HTTP response wrapper.
 */
final class ApiResponse {

  private const MAX_JSON_BYTES = 16777216;
  private const MAX_ERROR_JSON_BYTES = 65536;
  private const MAX_ERROR_MESSAGE_BYTES = 512;
  private const MAX_ERROR_CODE_BYTES = 64;

  private int $_status_code;

  /** @var array<string, list<string>> */
  private array $_headers;

  private string $_body;
  /** @var array<array-key, mixed>|null */
  private ?array $_json = null;
  private bool $_json_parsed = false;
  private ?string $_json_error = null;
  private bool $_json_scalar = false;

  /**
   * @param array<array-key, mixed> $headers
   */
  public function __construct(int $status_code, array $headers, string $body) {
    if ($status_code < 0 || $status_code > 999) {
      throw new \InvalidArgumentException('HTTP status code is invalid.');
    }

    $this->_status_code = $status_code;
    $this->_headers = self::_normalizeHeaders($headers);
    $this->_body = $body;
  }

  public function getStatusCode():int {
    return $this->_status_code;
  }

  /**
   * Return backward-compatible combined header values.
   *
   * @return array<string, string>
   */
  public function getHeaders():array {
    $combined = [];
    foreach ($this->_headers as $name => $values) {
      $combined[$name] = \implode(', ', $values);
    }

    return $combined;
  }

  /**
   * @return array<string, list<string>>
   */
  public function getHeadersMulti():array {
    return $this->_headers;
  }

  /**
   * Return all values for one response header in wire order.
   *
   * @return list<string>
   */
  public function getHeaderValues(string $name):array {
    return $this->_headers[\strtolower($name)] ?? [];
  }

  /**
   * Return repeated values combined with a comma and space.
   */
  public function getHeader(string $name):?string {
    $values = $this->getHeaderValues($name);
    return $values === [] ? null : \implode(', ', $values);
  }

  /**
   * The raw response may contain secrets or personal data. Do not log it.
   */
  public function getBody():string {
    return $this->_body;
  }

  /**
   * Decode a JSON object/array. Malformed or scalar JSON returns null; inspect
   * hasJsonError() and isJsonScalar() to distinguish those cases.
   */
  /**
   * @return array<array-key, mixed>|null
   */
  public function json():?array {
    if ($this->_json_parsed) {
      return $this->_json;
    }

    $this->_json_parsed = true;
    if ($this->_body === '') {
      return null;
    }

    if (\strlen($this->_body) > self::MAX_JSON_BYTES) {
      $this->_json_error = 'JSON response exceeds the parsing limit.';
      return null;
    }

    try {
      $decoded = \json_decode($this->_body, true, 512, \JSON_THROW_ON_ERROR);
    } catch (\JsonException) {
      $this->_json_error = 'Response body is not valid JSON.';
      return null;
    }

    if (!\is_array($decoded)) {
      $this->_json_scalar = true;
      return null;
    }

    $this->_json = $decoded;
    return $this->_json;
  }

  public function hasJsonError():bool {
    $this->json();
    return $this->_json_error !== null;
  }

  public function getJsonError():?string {
    $this->json();
    return $this->_json_error;
  }

  public function isJsonScalar():bool {
    $this->json();
    return $this->_json_scalar;
  }

  public function get(string $key, mixed $default = null):mixed {
    $data = $this->json();
    if ($data === null) {
      return $default;
    }

    foreach (\explode('.', $key) as $part) {
      if (!\is_array($data) || !\array_key_exists($part, $data)) {
        return $default;
      }
      $data = $data[$part];
    }

    return $data;
  }

  public function isSuccess():bool {
    return $this->_status_code >= 200 && $this->_status_code < 300;
  }

  /**
   * Every non-2xx response, including redirects, is an error.
   */
  public function isError():bool {
    return !$this->isSuccess();
  }

  public function isClientError():bool {
    return $this->_status_code >= 400 && $this->_status_code < 500;
  }

  public function isServerError():bool {
    return $this->_status_code >= 500 && $this->_status_code < 600;
  }

  public function throwIfError():self {
    if (!$this->isError()) {
      return $this;
    }

    $fallback_message = "HTTP {$this->_status_code}";
    $message = $fallback_message;
    $code = 'API_ERROR';

    if (\strlen($this->_body) <= self::MAX_ERROR_JSON_BYTES) {
      $json = $this->json();
      if ($json !== null) {
        $message = self::_safeRemoteValue(
          $json['message'] ?? $json['error'] ?? null,
          $fallback_message,
          self::MAX_ERROR_MESSAGE_BYTES
        );
        $code = self::_safeRemoteValue(
          $json['code'] ?? null,
          'API_ERROR',
          self::MAX_ERROR_CODE_BYTES
        );
      }
    }

    throw new ApiException($message, $code, $this);
  }

  /**
   * Return safe response metadata only. Raw bodies and response headers are
   * deliberately available solely through their explicit accessors.
   *
   * @return array{status_code: int, success: bool, body_length: int, json_error: ?string, json_scalar: bool}
   */
  public function toArray():array {
    return [
      'status_code' => $this->_status_code,
      'success' => $this->isSuccess(),
      'body_length' => \strlen($this->_body),
      'json_error' => $this->getJsonError(),
      'json_scalar' => $this->isJsonScalar(),
    ];
  }

  /**
   * @param array<array-key, mixed> $headers
   * @return array<string, list<string>>
   */
  private static function _normalizeHeaders(array $headers):array {
    $normalized = [];

    foreach ($headers as $name => $values) {
      if (!\is_string($name)) {
        continue;
      }
      $name = \strtolower(\trim($name));
      if ($name === '') {
        continue;
      }

      $values = \is_array($values) ? $values : [$values];
      foreach ($values as $value) {
        if (!\is_string($value)) {
          continue;
        }
        $normalized[$name] ??= [];
        $normalized[$name][] = $value;
      }
    }

    return $normalized;
  }

  private static function _safeRemoteValue(mixed $value, string $fallback, int $max_bytes):string {
    if (\is_int($value) || \is_float($value) || \is_bool($value)) {
      $value = (string) $value;
    }

    if (!\is_string($value)) {
      return $fallback;
    }

    $value = \preg_replace('/[\x00-\x1F\x7F]+/', ' ', $value) ?? '';
    $value = \trim($value);
    if ($value === '') {
      return $fallback;
    }

    if (\strlen($value) <= $max_bytes) {
      return $value;
    }

    $value = \substr($value, 0, $max_bytes);
    while ($value !== '' && \preg_match('//u', $value) !== 1) {
      $value = \substr($value, 0, -1);
    }

    return $value !== '' ? $value : $fallback;
  }
}
