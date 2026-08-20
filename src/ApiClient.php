<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client;

/**
 * HTTP client with built-in request signing.
 */
class ApiClient {

  public const MAX_TIMEOUT_SECONDS = 86400.0;

  private const JSON_FLAGS = \JSON_THROW_ON_ERROR
    | \JSON_UNESCAPED_SLASHES
    | \JSON_UNESCAPED_UNICODE
    | \JSON_PRESERVE_ZERO_FRACTION;

  private const RESERVED_AUTH_HEADERS = [
    'x-app-id',
    'x-public-key',
    'x-timestamp',
    'x-nonce',
    'x-body-hash',
    'x-signature',
  ];

  private Credentials $_credentials;
  private string $_base_url;
  private string $_origin;
  private string $_base_path;
  private float $_timeout;
  private float $_connect_timeout;

  /** @var array<string, string> */
  private array $_default_headers;

  private HttpTransportInterface $_transport;
  private bool $_allow_http_for_local_development;

  /**
   * The verify_ssl argument is retained for source compatibility. Passing
   * false is rejected; TLS peer and host verification cannot be disabled.
   *
   * @param array<array-key, mixed> $default_headers
   */
  public function __construct(
    Credentials $credentials,
    string $base_url,
    int|float $timeout = 30,
    array $default_headers = [],
    bool $verify_ssl = true,
    ?HttpTransportInterface $transport = null,
    int|float $connect_timeout = 10,
    bool $allow_http_for_local_development = false
  ) {
    if (!$verify_ssl) {
      throw new \InvalidArgumentException('TLS verification cannot be disabled.');
    }

    $this->_timeout = self::_validateTimeout($timeout, 'Total timeout');
    $this->_connect_timeout = self::_validateTimeout($connect_timeout, 'Connect timeout');
    $this->_allow_http_for_local_development = $allow_http_for_local_development;

    [$this->_base_url, $this->_origin, $this->_base_path] = self::_normalizeBaseUrl(
      $base_url,
      $allow_http_for_local_development
    );

    $this->_credentials = $credentials;
    $this->_default_headers = self::_normalizeHeaders($default_headers);
    $this->_transport = $transport ?? new CurlTransport();
  }

  /**
   * @param array<array-key, mixed> $query
   * @param array<array-key, mixed> $headers
   */
  public function get(string $path, array $query = [], array $headers = []):ApiResponse {
    if ($query !== []) {
      self::_preflightStructure($query, true);
      $query_string = \http_build_query(
        self::_normalizeStructuredData($query, true),
        '',
        '&',
        \PHP_QUERY_RFC3986
      );

      if ($query_string !== '') {
        $path .= \str_contains($path, '?') ? "&{$query_string}" : "?{$query_string}";
      }
    }

    return $this->request('GET', $path, '', $headers);
  }

  /**
   * @param array<array-key, mixed> $data
   * @param array<array-key, mixed> $headers
   */
  public function post(string $path, array $data = [], array $headers = []):ApiResponse {
    return $this->request('POST', $path, self::_encodeJson($data), $headers);
  }

  /**
   * @param array<array-key, mixed> $data
   * @param array<array-key, mixed> $headers
   */
  public function put(string $path, array $data = [], array $headers = []):ApiResponse {
    return $this->request('PUT', $path, self::_encodeJson($data), $headers);
  }

  /**
   * @param array<array-key, mixed> $data
   * @param array<array-key, mixed> $headers
   */
  public function patch(string $path, array $data = [], array $headers = []):ApiResponse {
    return $this->request('PATCH', $path, self::_encodeJson($data), $headers);
  }

  /**
   * @param array<array-key, mixed> $headers
   */
  public function delete(string $path, array $headers = []):ApiResponse {
    return $this->request('DELETE', $path, '', $headers);
  }

  /**
   * Make one raw request. The path is an already-built origin-form target and
   * is transmitted without parsing or re-encoding its query string.
   *
   * @param array<array-key, mixed> $headers
   */
  public function request(
    string $method,
    string $path,
    #[\SensitiveParameter]
    string $body = '',
    array $headers = []
  ):ApiResponse {
    $method = Signer::normalizeMethod($method);
    Signer::validateRequestTarget($path);

    $request_target = $this->_base_path . $path;
    Signer::validateRequestTarget($request_target);
    $url = $this->_origin . $request_target;

    $all_headers = \array_merge(
      $this->_default_headers,
      self::_normalizeHeaders($headers)
    );

    if ($body !== '' && !isset($all_headers['content-type'])) {
      $all_headers['content-type'] = 'application/json';
    }

    // Sign only after target and body construction are final.
    $auth_headers = Signer::generateHeaders(
      $this->_credentials,
      $method,
      $request_target,
      $body
    );

    foreach ($auth_headers as $name => $value) {
      $all_headers[\strtolower($name)] = $value;
    }

    $wire_headers = [];
    foreach ($all_headers as $name => $value) {
      $wire_headers[self::_displayHeaderName($name)] = $value;
    }

    return $this->_transport->send(new HttpRequest(
      $method,
      $url,
      $request_target,
      $wire_headers,
      $body,
      $this->_connect_timeout,
      $this->_timeout,
      $this->_allow_http_for_local_development
    ));
  }

  public function getBaseUrl():string {
    return $this->_base_url;
  }

  public function withBaseUrl(string $base_url):self {
    return new self(
      $this->_credentials,
      $base_url,
      $this->_timeout,
      $this->_default_headers,
      true,
      $this->_transport,
      $this->_connect_timeout,
      $this->_allow_http_for_local_development
    );
  }

  /**
   * @param array<array-key, mixed> $headers
   */
  public function withHeaders(array $headers):self {
    return new self(
      $this->_credentials,
      $this->_base_url,
      $this->_timeout,
      \array_merge($this->_default_headers, self::_normalizeHeaders($headers)),
      true,
      $this->_transport,
      $this->_connect_timeout,
      $this->_allow_http_for_local_development
    );
  }

  private static function _validateTimeout(int|float $timeout, string $label):float {
    $timeout = (float) $timeout;
    if (!\is_finite($timeout) || $timeout <= 0 || $timeout > self::MAX_TIMEOUT_SECONDS) {
      throw new \InvalidArgumentException(
        "{$label} must be finite, positive, and no greater than 86400 seconds."
      );
    }

    return $timeout;
  }

  /**
   * @return array{string, string, string}
   */
  private static function _normalizeBaseUrl(string $base_url, bool $allow_http):array {
    if (
      $base_url === ''
      || $base_url !== \trim($base_url)
      || \preg_match('/[\x00-\x20\x7F]/', $base_url)
    ) {
      throw new \InvalidArgumentException('Base URL is invalid.');
    }

    $parts = \parse_url($base_url);
    if (
      $parts === false
      || !isset($parts['scheme'], $parts['host'])
      || isset($parts['user'])
      || isset($parts['pass'])
      || isset($parts['query'])
      || isset($parts['fragment'])
    ) {
      throw new \InvalidArgumentException('Base URL must contain only an HTTP origin and optional path.');
    }

    $scheme = \strtolower($parts['scheme']);
    [$host, $host_for_url] = self::_normalizeHost($parts['host']);
    if ($scheme !== 'https') {
      if ($scheme !== 'http' || !$allow_http || !self::_isLoopbackHost($host)) {
        throw new \InvalidArgumentException('HTTPS is required except for explicitly enabled loopback development.');
      }
    }

    $origin = "{$scheme}://{$host_for_url}";
    if (isset($parts['port'])) {
      $origin .= ':' . $parts['port'];
    }

    $base_path = $parts['path'] ?? '';
    if ($base_path !== '' && !\str_starts_with($base_path, '/')) {
      throw new \InvalidArgumentException('Base URL path is invalid.');
    }
    $base_path = \rtrim($base_path, '/');

    return [$origin . $base_path, $origin, $base_path];
  }

  private static function _isLoopbackHost(string $host):bool {
    return $host === 'localhost' || $host === '127.0.0.1' || $host === '::1';
  }

  /**
   * Return separate comparison and URL-rendering forms for a parsed host.
   *
   * PHP may retain IPv6 brackets in parse_url()['host']; normalizing them once
   * prevents loopback mismatches and doubled brackets.
   *
   * @return array{non-empty-string, non-empty-string}
   */
  private static function _normalizeHost(string $host):array {
    $host = \strtolower($host);
    $starts_bracket = \str_starts_with($host, '[');
    $ends_bracket = \str_ends_with($host, ']');

    if ($starts_bracket !== $ends_bracket) {
      throw new \InvalidArgumentException('Base URL host is invalid.');
    }

    if ($starts_bracket) {
      $host = \substr($host, 1, -1);
    }

    if ($host === '' || \str_contains($host, '[') || \str_contains($host, ']')) {
      throw new \InvalidArgumentException('Base URL host is invalid.');
    }

    $rendered = \str_contains($host, ':') ? "[{$host}]" : $host;
    return [$host, $rendered];
  }

  /**
   * @param array<array-key, mixed> $headers
   * @return array<string, string>
   */
  private static function _normalizeHeaders(#[\SensitiveParameter] array $headers):array {
    $normalized = [];

    foreach ($headers as $name => $value) {
      if (!\is_string($name) || !\preg_match('/\A[!#$%&\'*+.^_`|~0-9A-Za-z-]+\z/D', $name)) {
        throw new \InvalidArgumentException('Header names must be valid HTTP tokens.');
      }

      $lower_name = \strtolower($name);
      if (\in_array($lower_name, self::RESERVED_AUTH_HEADERS, true)) {
        throw new \InvalidArgumentException('Authentication headers are managed by the client.');
      }

      if (!\is_scalar($value)) {
        throw new \InvalidArgumentException('Header values must be scalar.');
      }

      $string_value = (string) $value;
      if (
        \strlen($string_value) > 8192
        || \str_contains($string_value, "\r")
        || \str_contains($string_value, "\n")
        || \str_contains($string_value, "\0")
      ) {
        throw new \InvalidArgumentException('Header values must be bounded and free of line breaks.');
      }

      $normalized[$lower_name] = $string_value;
    }

    return $normalized;
  }

  private static function _displayHeaderName(string $name):string {
    return \implode('-', \array_map(
      static fn(string $part):string => \ucfirst($part),
      \explode('-', \strtolower($name))
    ));
  }

  /**
   * Sort associative maps recursively while preserving list order.
   *
   * @param array<array-key, mixed> $data
   * @return array<array-key, mixed>
   */
  private static function _normalizeStructuredData(array $data, bool $for_query):array {
    $normalized = [];
    foreach ($data as $key => $value) {
      if (\is_array($value)) {
        $value = self::_normalizeStructuredData($value, $for_query);
      } elseif (\is_object($value) || \is_resource($value)) {
        throw new ClientConfigurationException(
          $for_query ? 'Query data contains an unsupported value.' : 'JSON data contains an unsupported value.',
          $for_query ? 'QUERY_ENCODING_ERROR' : 'JSON_ENCODING_ERROR'
        );
      } elseif ($for_query && \is_float($value) && !\is_finite($value)) {
        throw new ClientConfigurationException(
          'Query data contains a non-finite number.',
          'QUERY_ENCODING_ERROR'
        );
      }

      $normalized[$key] = $value;
    }

    if (!\array_is_list($normalized)) {
      \ksort($normalized, \SORT_STRING);
    }

    return $normalized;
  }

  /**
   * @param array<array-key, mixed> $data
   */
  private static function _encodeJson(#[\SensitiveParameter] array $data):string {
    try {
      self::_preflightStructure($data, false);
      return \json_encode(self::_normalizeStructuredData($data, false), self::JSON_FLAGS);
    } catch (\JsonException $exception) {
      throw new ClientConfigurationException(
        'Request JSON could not be encoded.',
        'JSON_ENCODING_ERROR',
        null,
        $exception
      );
    }
  }

  /**
   * Let ext-json detect recursion, invalid UTF-8, non-finite numbers, and
   * unsupported values before recursive deterministic sorting begins.
   *
   * @param array<array-key, mixed> $data
   */
  private static function _preflightStructure(#[\SensitiveParameter] array $data, bool $for_query):void {
    try {
      \json_encode($data, \JSON_THROW_ON_ERROR);
    } catch (\JsonException $exception) {
      throw new ClientConfigurationException(
        $for_query ? 'Query data could not be encoded.' : 'Request JSON could not be encoded.',
        $for_query ? 'QUERY_ENCODING_ERROR' : 'JSON_ENCODING_ERROR',
        null,
        $exception
      );
    }
  }
}
