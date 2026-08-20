<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client\Tests;

use PHPUnit\Framework\TestCase;
use TimeFrontiers\Auth\Client\{ApiClient, ApiException, ApiResponse, Credentials, CurlTransport};
use TimeFrontiers\Auth\Client\Tests\Support\LoopbackServer;

final class CurlTransportTest extends TestCase {

  public function testFinalHeaderBlockAndRepeatedValuesArePreserved():void {
    $raw = "HTTP/1.1 200 Connection established\r\nProxy-Agent: test\r\n\r\n"
      . "HTTP/1.1 100 Continue\r\nInterim: yes\r\n\r\n"
      . "HTTP/2 201 Created\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nX-Final: yes\r\n\r\n";

    self::assertSame([
      'set-cookie' => ['a=1', 'b=2'],
      'x-final' => ['yes'],
    ], CurlTransport::parseResponseHeaders($raw));
  }

  public function testMalformedHeaderInputProducesNoInventedHeaders():void {
    self::assertSame([], CurlTransport::parseResponseHeaders("X-Value: one\r\n\r\n"));
  }

  public function testDefaultTransportSendsExactTargetAndZeroBodyWithoutPhpIssues():void {
    $server = LoopbackServer::start();
    $target = '/probe/a/./b/../c/%7euser?x=%2f%3a&space=hello%20world';

    try {
      $client = new ApiClient(
        new Credentials('app-1', 'selector-1', 'test-only-secret'),
        "http://127.0.0.1:{$server->getPort()}",
        timeout: 2,
        connect_timeout: 1,
        allow_http_for_local_development: true
      );

      $response = $this->_withoutPhpIssues(
        static fn():ApiResponse => $client->request('POST', $target, '0')
      );
      $record = $server->awaitRequest();

      self::assertSame("POST {$target} HTTP/1.1", $record['request_line']);
      self::assertSame($target, $record['request_target']);
      self::assertSame('0', $record['body']);
      self::assertSame(201, $response->getStatusCode());
      self::assertSame(['a=1', 'b=2'], $response->getHeaderValues('set-cookie'));
      self::assertSame('yes', $response->getHeader('x-final'));
      self::assertSame('OK', $response->getBody());
    } finally {
      $server->stop();
    }
  }

  public function testDefaultTransportFailureDoesNotEmitPhpIssues():void {
    $server = LoopbackServer::start();
    $port = $server->getPort();
    $server->stop();

    $client = new ApiClient(
      new Credentials('app-1', 'selector-1', 'test-only-secret'),
      "http://127.0.0.1:{$port}",
      timeout: 0.5,
      connect_timeout: 0.25,
      allow_http_for_local_development: true
    );

    try {
      $this->_withoutPhpIssues(static fn():ApiResponse => $client->get('/unreachable'));
      self::fail('A closed loopback port should produce a transport failure.');
    } catch (ApiException $exception) {
      self::assertSame('TRANSPORT_ERROR', $exception->getErrorCode());
      self::assertStringNotContainsString('test-only-secret', $exception->getMessage());
    }
  }

  /**
   * @template T
   * @param callable(): T $operation
   * @return T
   */
  private function _withoutPhpIssues(callable $operation):mixed {
    \set_error_handler(
      static function(int $severity, string $message, string $file, int $line):never {
        throw new \ErrorException($message, 0, $severity, $file, $line);
      }
    );

    try {
      return $operation();
    } finally {
      \restore_error_handler();
    }
  }
}
