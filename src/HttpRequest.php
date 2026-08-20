<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client;

/**
 * Immutable request passed to an HTTP transport.
 */
final class HttpRequest {

  private const MAX_TIMEOUT_SECONDS = 86400.0;

  /** @var non-empty-string */
  private string $_method;
  /** @var non-empty-string */
  private string $_url;
  /** @var non-empty-string */
  private string $_request_target;

  /** @var array<string, string> */
  private array $_headers;

  private string $_body;
  private float $_connect_timeout;
  private float $_total_timeout;
  private bool $_allow_http_for_local_development;

  /**
   * @param array<string, string> $headers
   */
  public function __construct(
    string $method,
    string $url,
    string $request_target,
    #[\SensitiveParameter]
    array $headers,
    #[\SensitiveParameter]
    string $body,
    float $connect_timeout,
    float $total_timeout,
    bool $allow_http_for_local_development
  ) {
    $method = Signer::normalizeMethod($method);
    if ($request_target === '') {
      throw new \InvalidArgumentException('HTTP request target is required.');
    }
    Signer::validateRequestTarget($request_target);

    $parts = \parse_url($url);
    if (
      $url === ''
      || $parts === false
      || !isset($parts['scheme'], $parts['host'])
      || isset($parts['user'])
      || isset($parts['pass'])
      || isset($parts['fragment'])
    ) {
      throw new \InvalidArgumentException('HTTP request URL is invalid.');
    }

    $scheme = \strtolower($parts['scheme']);
    $host = self::_comparisonHost($parts['host']);
    $loopback = $host === 'localhost' || $host === '127.0.0.1' || $host === '::1';
    if ($scheme !== 'https' && ($scheme !== 'http' || !$allow_http_for_local_development || !$loopback)) {
      throw new \InvalidArgumentException('HTTP transport requires HTTPS or explicit loopback development.');
    }

    $url_target = $parts['path'] ?? '/';
    if (isset($parts['query'])) {
      $url_target .= '?' . $parts['query'];
    }
    if ($url_target !== $request_target) {
      throw new \InvalidArgumentException('HTTP URL and signed request target must match exactly.');
    }

    if (
      !\is_finite($connect_timeout)
      || $connect_timeout <= 0
      || $connect_timeout > self::MAX_TIMEOUT_SECONDS
      || !\is_finite($total_timeout)
      || $total_timeout <= 0
      || $total_timeout > self::MAX_TIMEOUT_SECONDS
    ) {
      throw new \InvalidArgumentException(
        'HTTP transport timeouts must be finite, positive, and no greater than 86400 seconds.'
      );
    }

    $this->_method = $method;
    $this->_url = $url;
    $this->_request_target = $request_target;
    $this->_headers = $headers;
    $this->_body = $body;
    $this->_connect_timeout = $connect_timeout;
    $this->_total_timeout = $total_timeout;
    $this->_allow_http_for_local_development = $allow_http_for_local_development;
  }

  /** @return non-empty-string */
  private static function _comparisonHost(string $host):string {
    $host = \strtolower($host);
    $starts_bracket = \str_starts_with($host, '[');
    $ends_bracket = \str_ends_with($host, ']');

    if ($starts_bracket !== $ends_bracket) {
      throw new \InvalidArgumentException('HTTP request host is invalid.');
    }

    if ($starts_bracket) {
      $host = \substr($host, 1, -1);
    }

    if ($host === '' || \str_contains($host, '[') || \str_contains($host, ']')) {
      throw new \InvalidArgumentException('HTTP request host is invalid.');
    }

    return $host;
  }

  /** @return non-empty-string */
  public function getMethod():string {
    return $this->_method;
  }

  /** @return non-empty-string */
  public function getUrl():string {
    return $this->_url;
  }

  /** @return non-empty-string */
  public function getRequestTarget():string {
    return $this->_request_target;
  }

  /**
   * @return array<string, string>
   */
  public function getHeaders():array {
    return $this->_headers;
  }

  /**
   * The body may contain secrets or personal data. Do not log it.
   */
  public function getBody():string {
    return $this->_body;
  }

  public function getConnectTimeout():float {
    return $this->_connect_timeout;
  }

  public function getTotalTimeout():float {
    return $this->_total_timeout;
  }

  public function shouldVerifyTlsPeer():bool {
    return true;
  }

  /** @return 2 */
  public function getTlsVerifyHost():int {
    return 2;
  }

  public function shouldFollowRedirects():bool {
    return false;
  }

  /**
   * @return list<string>
   */
  public function getAllowedProtocols():array {
    return $this->_allow_http_for_local_development ? ['https', 'http'] : ['https'];
  }
}
