<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client;

/**
 * Secure-by-default cURL transport.
 */
final class CurlTransport implements HttpTransportInterface {

  private const MAX_TIMEOUT_SECONDS = 86400.0;

  public function send(HttpRequest $request):ApiResponse {
    $handle = \curl_init();
    if ($handle === false) {
      throw new ApiException('HTTP transport could not be initialized.', 'TRANSPORT_INIT_ERROR');
    }

    try {
      $headers = self::_formatHeaders($request->getHeaders());
      $protocols = \CURLPROTO_HTTPS;
      if (\in_array('http', $request->getAllowedProtocols(), true)) {
        $protocols |= \CURLPROTO_HTTP;
      }

      $options = [
        \CURLOPT_URL => $request->getUrl(),
        \CURLOPT_REQUEST_TARGET => $request->getRequestTarget(),
        \CURLOPT_PATH_AS_IS => true,
        \CURLOPT_RETURNTRANSFER => true,
        \CURLOPT_HEADER => true,
        \CURLOPT_CONNECTTIMEOUT_MS => self::_milliseconds($request->getConnectTimeout()),
        \CURLOPT_TIMEOUT_MS => self::_milliseconds($request->getTotalTimeout()),
        \CURLOPT_HTTPHEADER => $headers,
        \CURLOPT_SSL_VERIFYPEER => $request->shouldVerifyTlsPeer(),
        \CURLOPT_SSL_VERIFYHOST => $request->getTlsVerifyHost(),
        \CURLOPT_FOLLOWLOCATION => $request->shouldFollowRedirects(),
        \CURLOPT_MAXREDIRS => 0,
        \CURLOPT_PROTOCOLS => $protocols,
        \CURLOPT_NOSIGNAL => true,
      ];

      if (\defined('CURLOPT_REDIR_PROTOCOLS')) {
        $options[\CURLOPT_REDIR_PROTOCOLS] = $protocols;
      }

      if ($request->getBody() !== '') {
        $options[\CURLOPT_POSTFIELDS] = $request->getBody();
      }

      // Set the custom method after POSTFIELDS so cURL sends the requested verb.
      $options[\CURLOPT_CUSTOMREQUEST] = $request->getMethod();

      if (!\curl_setopt_array($handle, $options)) {
        throw new ApiException('HTTP transport options could not be applied.', 'TRANSPORT_CONFIG_ERROR');
      }

      $raw_response = \curl_exec($handle);
      if (!\is_string($raw_response)) {
        $errno = \curl_errno($handle);
        throw new ApiException("HTTP transport failed (cURL error {$errno}).", 'TRANSPORT_ERROR');
      }

      $status_code = (int) \curl_getinfo($handle, \CURLINFO_HTTP_CODE);
      $header_size = (int) \curl_getinfo($handle, \CURLINFO_HEADER_SIZE);
      $header_string = \substr($raw_response, 0, $header_size);
      $body = \substr($raw_response, $header_size);

      return new ApiResponse($status_code, self::parseResponseHeaders($header_string), $body);
    } finally {
      // CurlHandle objects release their native resources when destroyed.
      // curl_close() is deprecated and a no-op on the PHP 8.5 release floor.
      unset($handle);
    }
  }

  /**
   * Parse only the final HTTP response header block and preserve duplicates.
   *
   * @return array<string, list<string>>
   */
  public static function parseResponseHeaders(string $header_string):array {
    $blocks = \preg_split('/\r\n\r\n|\n\n|\r\r/', \trim($header_string));
    if ($blocks === false) {
      return [];
    }

    $final_block = '';
    foreach ($blocks as $block) {
      if (\preg_match('/\AHTTP\/\d(?:\.\d)?\s+\d{3}\b/i', \ltrim($block))) {
        $final_block = $block;
      }
    }

    if ($final_block === '') {
      return [];
    }

    $lines = \preg_split('/\r\n|\n|\r/', $final_block);
    if ($lines === false) {
      return [];
    }

    $headers = [];
    foreach (\array_slice($lines, 1) as $line) {
      if (!\str_contains($line, ':')) {
        continue;
      }

      [$name, $value] = \explode(':', $line, 2);
      $name = \strtolower(\trim($name));
      if ($name === '') {
        continue;
      }

      $headers[$name] ??= [];
      $headers[$name][] = \trim($value);
    }

    return $headers;
  }

  /**
   * @param array<string, string> $headers
   * @return list<string>
   */
  private static function _formatHeaders(#[\SensitiveParameter] array $headers):array {
    $lines = [];
    foreach ($headers as $name => $value) {
      if (
        !\preg_match('/\A[!#$%&\'*+.^_`|~0-9A-Za-z-]+\z/D', $name)
        || \str_contains($value, "\r")
        || \str_contains($value, "\n")
      ) {
        throw new ApiException('HTTP header is not safe to transmit.', 'TRANSPORT_HEADER_ERROR');
      }
      $lines[] = "{$name}: {$value}";
    }

    return $lines;
  }

  private static function _milliseconds(float $seconds):int {
    if (!\is_finite($seconds) || $seconds <= 0 || $seconds > self::MAX_TIMEOUT_SECONDS) {
      throw new ApiException('HTTP transport timeout is outside the supported range.', 'TRANSPORT_CONFIG_ERROR');
    }

    $milliseconds = \ceil($seconds * 1000);
    if ($milliseconds < 1 || $milliseconds > \PHP_INT_MAX) {
      throw new ApiException('HTTP transport timeout cannot be represented safely.', 'TRANSPORT_CONFIG_ERROR');
    }

    return (int) $milliseconds;
  }
}
