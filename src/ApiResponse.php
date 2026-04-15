<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client;

/**
 * Response wrapper for API calls.
 *
 * Provides convenient access to response data, status codes,
 * and error handling.
 */
final class ApiResponse {

  private int $_status_code;
  private array $_headers;
  private string $_body;
  private ?array $_json = null;
  private bool $_json_parsed = false;

  public function __construct(int $status_code, array $headers, string $body) {
    $this->_status_code = $status_code;
    $this->_headers = $headers;
    $this->_body = $body;
  }

  /**
   * Get the HTTP status code.
   */
  public function getStatusCode():int {
    return $this->_status_code;
  }

  /**
   * Get all response headers.
   */
  public function getHeaders():array {
    return $this->_headers;
  }

  /**
   * Get a specific header value.
   */
  public function getHeader(string $name):?string {
    $name = \strtolower($name);
    return $this->_headers[$name] ?? null;
  }

  /**
   * Get the raw response body.
   */
  public function getBody():string {
    return $this->_body;
  }

  /**
   * Parse and return the response body as JSON.
   *
   * @return array|null Decoded JSON or null if invalid
   */
  public function json():?array {
    if (!$this->_json_parsed) {
      $this->_json_parsed = true;

      if (empty($this->_body)) {
        $this->_json = null;
      } else {
        $decoded = \json_decode($this->_body, true);
        $this->_json = \is_array($decoded) ? $decoded : null;
      }
    }

    return $this->_json;
  }

  /**
   * Get a value from the JSON response.
   *
   * @param string $key Dot-notation key (e.g., "data.user.name")
   * @param mixed $default Default value if key not found
   */
  public function get(string $key, mixed $default = null):mixed {
    $data = $this->json();
    if ($data === null) {
      return $default;
    }

    $keys = \explode('.', $key);
    foreach ($keys as $k) {
      if (!\is_array($data) || !\array_key_exists($k, $data)) {
        return $default;
      }
      $data = $data[$k];
    }

    return $data;
  }

  /**
   * Check if the request was successful (2xx status).
   */
  public function isSuccess():bool {
    return $this->_status_code >= 200 && $this->_status_code < 300;
  }

  /**
   * Check if the request failed (4xx or 5xx status).
   */
  public function isError():bool {
    return $this->_status_code >= 400;
  }

  /**
   * Check if the request was a client error (4xx status).
   */
  public function isClientError():bool {
    return $this->_status_code >= 400 && $this->_status_code < 500;
  }

  /**
   * Check if the request was a server error (5xx status).
   */
  public function isServerError():bool {
    return $this->_status_code >= 500;
  }

  /**
   * Throw an exception if the request failed.
   *
   * @throws ApiException
   */
  public function throwIfError():self {
    if ($this->isError()) {
      $json = $this->json();
      $message = $json['message'] ?? $json['error'] ?? "HTTP {$this->_status_code}";
      $code = $json['code'] ?? 'API_ERROR';

      throw new ApiException($message, $code, $this);
    }

    return $this;
  }

  /**
   * Convert to array for debugging.
   */
  public function toArray():array {
    return [
      'status_code' => $this->_status_code,
      'headers' => $this->_headers,
      'body' => $this->_body,
      'json' => $this->json(),
    ];
  }
}
