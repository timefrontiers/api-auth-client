<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client\Tests;

use PHPUnit\Framework\TestCase;
use TimeFrontiers\Auth\Client\HttpRequest;

final class HttpRequestTest extends TestCase {

  public function testDirectTransportRequestsCannotBypassUrlOrTargetPolicy():void {
    $unsafe = [
      ['http://example.test/ping', '/ping', true],
      ['https://example.test/actual', '/signed', false],
      ['https://user:pass@example.test/ping', '/ping', false],
      ['https://example.test/ping#fragment', '/ping', false],
    ];

    foreach ($unsafe as [$url, $target, $allow_http]) {
      try {
        new HttpRequest('GET', $url, $target, [], '', 1.0, 2.0, $allow_http);
        self::fail("Unsafe request should be rejected: {$url}");
      } catch (\InvalidArgumentException) {
        self::addToAssertionCount(1);
      }
    }
  }

  public function testExplicitLoopbackHttpRequestIsAllowed():void {
    $request = new HttpRequest(
      'get',
      'http://127.0.0.1:8080/ping?q=one',
      '/ping?q=one',
      [],
      '',
      1.0,
      2.0,
      true
    );

    self::assertSame('GET', $request->getMethod());
    self::assertSame(['https', 'http'], $request->getAllowedProtocols());
  }

  public function testBracketedIpv6LoopbackAndTimeoutBoundariesAreHandled():void {
    $request = new HttpRequest(
      'GET',
      'http://[::1]:8080/ping',
      '/ping',
      [],
      '',
      0.000001,
      86400.0,
      true
    );

    self::assertSame('http://[::1]:8080/ping', $request->getUrl());
    self::assertSame(86400.0, $request->getTotalTimeout());

    $this->expectException(\InvalidArgumentException::class);
    new HttpRequest(
      'GET',
      'https://[2001:db8::1]/ping',
      '/ping',
      [],
      '',
      1.0,
      86400.001,
      false
    );
  }
}
