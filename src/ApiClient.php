<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client;

/**
 * HTTP client with built-in request signing.
 *
 * All requests are automatically signed using the provided credentials.
 *
 * Usage:
 *   $client = new ApiClient($credentials, 'https://api.example.com');
 *   $response = $client->get('/users');
 *   $response = $client->post('/users', ['name' => 'John']);
 */
class ApiClient {

  private Credentials $_credentials;
  private string $_base_url;
  private int $_timeout;
  private array $_default_headers;
  private bool $_verify_ssl;

  public function __construct(
    Credentials $credentials,
    string $base_url,
    int $timeout = 30,
    array $default_headers = [],
    bool $verify_ssl = true
  ) {
    $this->_credentials = $credentials;
    $this->_base_url = \rtrim($base_url, '/');
    $this->_timeout = $timeout;
    $this->_default_headers = $default_headers;
    $this->_verify_ssl = $verify_ssl;
  }

  /**
   * Make a GET request.
   */
  public function get(string $path, array $query = [], array $headers = []):ApiResponse {
    if (!empty($query)) {
      $path .= '?' . \http_build_query($query);
    }
    return $this->request('GET', $path, '', $headers);
  }

  /**
   * Make a POST request.
   */
  public function post(string $path, array $data = [], array $headers = []):ApiResponse {
    $body = \json_encode($data);
    return $this->request('POST', $path, $body, $headers);
  }

  /**
   * Make a PUT request.
   */
  public function put(string $path, array $data = [], array $headers = []):ApiResponse {
    $body = \json_encode($data);
    return $this->request('PUT', $path, $body, $headers);
  }

  /**
   * Make a PATCH request.
   */
  public function patch(string $path, array $data = [], array $headers = []):ApiResponse {
    $body = \json_encode($data);
    return $this->request('PATCH', $path, $body, $headers);
  }

  /**
   * Make a DELETE request.
   */
  public function delete(string $path, array $headers = []):ApiResponse {
    return $this->request('DELETE', $path, '', $headers);
  }

  /**
   * Make a raw request with a string body.
   */
  public function request(
    string $method,
    string $path,
    string $body = '',
    array $headers = []
  ):ApiResponse {
    $url = $this->_base_url . $path;
    $method = \strtoupper($method);

    // Generate auth headers
    $auth_headers = Signer::generateHeaders(
      $this->_credentials,
      $method,
      $path,
      $body
    );

    // Merge headers: defaults < auth < custom
    $all_headers = \array_merge(
      $this->_default_headers,
      $auth_headers,
      $headers
    );

    // Add Content-Type if body present and not set
    if (!empty($body) && !isset($all_headers['Content-Type'])) {
      $all_headers['Content-Type'] = 'application/json';
    }

    // Format headers for cURL
    $curl_headers = [];
    foreach ($all_headers as $name => $value) {
      $curl_headers[] = "{$name}: {$value}";
    }

    // Execute request
    return $this->_execute($method, $url, $body, $curl_headers);
  }

  /**
   * Execute the cURL request.
   */
  private function _execute(
    string $method,
    string $url,
    string $body,
    array $headers
  ):ApiResponse {
    $ch = \curl_init();

    \curl_setopt_array($ch, [
      CURLOPT_URL => $url,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_HEADER => true,
      CURLOPT_TIMEOUT => $this->_timeout,
      CURLOPT_HTTPHEADER => $headers,
      CURLOPT_SSL_VERIFYPEER => $this->_verify_ssl,
      CURLOPT_SSL_VERIFYHOST => $this->_verify_ssl ? 2 : 0,
    ]);

    // Set method
    switch ($method) {
      case 'POST':
        \curl_setopt($ch, CURLOPT_POST, true);
        break;
      case 'PUT':
      case 'PATCH':
      case 'DELETE':
        \curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        break;
    }

    // Set body
    if (!empty($body)) {
      \curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }

    // Execute
    $response = \curl_exec($ch);

    if ($response === false) {
      $error = \curl_error($ch);
      $errno = \curl_errno($ch);
      // \curl_close($ch);
      throw new ApiException("cURL error ({$errno}): {$error}", 'CURL_ERROR');
    }

    $status_code = \curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $header_size = \curl_getinfo($ch, CURLINFO_HEADER_SIZE);

    // \curl_close($ch);

    // Split headers and body
    $header_string = \substr($response, 0, $header_size);
    $body_string = \substr($response, $header_size);

    // Parse headers
    $response_headers = $this->_parseHeaders($header_string);

    return new ApiResponse($status_code, $response_headers, $body_string);
  }

  /**
   * Parse response headers into an array.
   */
  private function _parseHeaders(string $header_string):array {
    $headers = [];
    $lines = \explode("\r\n", $header_string);

    foreach ($lines as $line) {
      if (\str_contains($line, ':')) {
        [$name, $value] = \explode(':', $line, 2);
        $headers[\strtolower(\trim($name))] = \trim($value);
      }
    }

    return $headers;
  }

  /**
   * Get the base URL.
   */
  public function getBaseUrl():string {
    return $this->_base_url;
  }

  /**
   * Create a new client with a different base URL.
   */
  public function withBaseUrl(string $base_url):self {
    return new self(
      $this->_credentials,
      $base_url,
      $this->_timeout,
      $this->_default_headers,
      $this->_verify_ssl
    );
  }

  /**
   * Create a new client with additional default headers.
   */
  public function withHeaders(array $headers):self {
    return new self(
      $this->_credentials,
      $this->_base_url,
      $this->_timeout,
      \array_merge($this->_default_headers, $headers),
      $this->_verify_ssl
    );
  }
}
