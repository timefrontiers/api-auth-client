<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client\Tests;

use PHPUnit\Framework\TestCase;
use TimeFrontiers\Auth\Client\{
  ApiClient,
  ClientConfigurationException,
  Credentials,
  Signer
};
use TimeFrontiers\Auth\Client\Tests\Support\FakeTransport;

final class ApiClientTest extends TestCase {

  private Credentials $_credentials;

  protected function setUp():void {
    $this->_credentials = new Credentials('app-1', 'selector-1', 'test-secret');
  }

  public function testFinalTargetIsSignedExactlyAsTransmitted():void {
    $transport = new FakeTransport();
    $client = new ApiClient($this->_credentials, 'https://example.test/api', transport: $transport);

    $client->get('/search', [
      'sort' => ['direction' => 'asc', 'by' => 'name'],
      'q' => 'hello world',
      'filter' => ['tags' => ['red', 'blue']],
    ]);

    $request = $transport->requests[0];
    $expected = '/api/search?filter%5Btags%5D%5B0%5D=red'
      . '&filter%5Btags%5D%5B1%5D=blue&q=hello%20world'
      . '&sort%5Bby%5D=name&sort%5Bdirection%5D=asc';

    self::assertSame($expected, $request->getRequestTarget());
    self::assertSame('https://example.test' . $expected, $request->getUrl());

    $headers = $request->getHeaders();
    self::assertTrue(Signer::verifySignature(
      $headers[Signer::HEADER_SIGNATURE],
      'test-secret',
      'app-1',
      'GET',
      $request->getRequestTarget(),
      (int) $headers[Signer::HEADER_TIMESTAMP],
      $headers[Signer::HEADER_NONCE]
    ));
  }

  public function testJsonIsDeterministicUtf8AndEncodingFailureDoesNotSend():void {
    $transport = new FakeTransport();
    $client = new ApiClient($this->_credentials, 'https://example.test', transport: $transport);
    $client->post('/messages', ['z' => 'Olá 世界', 'a' => 1]);

    self::assertSame('{"a":1,"z":"Olá 世界"}', $transport->requests[0]->getBody());

    try {
      $client->post('/messages', ['invalid' => "\xB1\x31"]);
      self::fail('Invalid UTF-8 should not be sent.');
    } catch (ClientConfigurationException $exception) {
      self::assertSame('JSON_ENCODING_ERROR', $exception->getErrorCode());
      self::assertSame('Request JSON could not be encoded.', $exception->getMessage());
    }

    self::assertCount(1, $transport->requests);

    $recursive = [];
    $recursive['self'] = &$recursive;
    try {
      $client->post('/messages', $recursive);
      self::fail('Recursive JSON should not be sent.');
    } catch (ClientConfigurationException $exception) {
      self::assertSame('JSON_ENCODING_ERROR', $exception->getErrorCode());
    }

    self::assertCount(1, $transport->requests);
  }

  public function testZeroBodyIsSentAndHashed():void {
    $transport = new FakeTransport();
    $client = new ApiClient($this->_credentials, 'https://example.test', transport: $transport);
    $client->request('POST', '/value', '0');

    $request = $transport->requests[0];
    self::assertSame('0', $request->getBody());
    self::assertSame(Signer::hashBody('0'), $request->getHeaders()[Signer::HEADER_BODY_HASH]);
  }

  public function testAuthenticationHeadersCannotBeOverriddenInAnyCase():void {
    foreach (['X-App-Id', 'x-signature', 'X-PuBlIc-KeY'] as $name) {
      try {
        new ApiClient(
          $this->_credentials,
          'https://example.test',
          default_headers: [$name => 'replacement'],
          transport: new FakeTransport()
        );
        self::fail("Reserved header should be rejected: {$name}");
      } catch (\InvalidArgumentException) {
        self::addToAssertionCount(1);
      }
    }

    $client = new ApiClient($this->_credentials, 'https://example.test', transport: new FakeTransport());
    $this->expectException(\InvalidArgumentException::class);
    $client->get('/ping', headers: ['x-NoNcE' => 'replacement']);
  }

  public function testHeaderNamesAreCaseInsensitiveAndInjectionIsRejected():void {
    $transport = new FakeTransport();
    $client = new ApiClient(
      $this->_credentials,
      'https://example.test',
      default_headers: ['content-type' => 'text/plain'],
      transport: $transport
    );
    $client->request('POST', '/value', '{}', ['Content-Type' => 'application/custom']);

    $headers = $transport->requests[0]->getHeaders();
    self::assertSame('application/custom', $headers['Content-Type']);
    self::assertCount(1, \array_filter(
      \array_keys($headers),
      static fn(string $name):bool => \strtolower($name) === 'content-type'
    ));

    $this->expectException(\InvalidArgumentException::class);
    $client->get('/ping', headers: ['X-Value' => "safe\r\nX-Injected: yes"]);
  }

  public function testSecureTransportOptionsAreFixedAndHttpIsLoopbackOnly():void {
    $transport = new FakeTransport();
    $client = new ApiClient(
      $this->_credentials,
      'https://example.test',
      timeout: 20.5,
      transport: $transport,
      connect_timeout: 2.25
    );
    $client->get('/ping');

    $request = $transport->requests[0];
    self::assertTrue($request->shouldVerifyTlsPeer());
    self::assertSame(2, $request->getTlsVerifyHost());
    self::assertFalse($request->shouldFollowRedirects());
    self::assertSame(['https'], $request->getAllowedProtocols());
    self::assertSame(2.25, $request->getConnectTimeout());
    self::assertSame(20.5, $request->getTotalTimeout());

    $local_transport = new FakeTransport();
    $local = new ApiClient(
      $this->_credentials,
      'http://127.0.0.1:8080',
      transport: $local_transport,
      allow_http_for_local_development: true
    );
    $local->get('/ping');
    self::assertSame(['https', 'http'], $local_transport->requests[0]->getAllowedProtocols());
  }

  public function testInvalidBaseUrlsTlsSwitchAndTimeoutsAreRejected():void {
    $invalid = [
      ['ftp://example.test', 30, true, 10, false],
      ['http://example.test', 30, true, 10, true],
      ['https://user:pass@example.test', 30, true, 10, false],
      ['https://example.test?query=1', 30, true, 10, false],
      ['https://example.test', 0, true, 10, false],
      ['https://example.test', 30, true, \INF, false],
      ['https://example.test', \PHP_FLOAT_MAX, true, 10, false],
      ['https://example.test', 30, true, ApiClient::MAX_TIMEOUT_SECONDS + 0.001, false],
      ['https://example.test', 30, false, 10, false],
    ];

    foreach ($invalid as [$url, $timeout, $verify, $connect, $allow_http]) {
      try {
        new ApiClient(
          $this->_credentials,
          $url,
          $timeout,
          verify_ssl: $verify,
          transport: new FakeTransport(),
          connect_timeout: $connect,
          allow_http_for_local_development: $allow_http
        );
        self::fail("Unsafe configuration should be rejected: {$url}");
      } catch (\InvalidArgumentException) {
        self::addToAssertionCount(1);
      }
    }
  }

  public function testTimeoutBoundariesRemainFiniteAndRepresentable():void {
    $transport = new FakeTransport();
    $client = new ApiClient(
      $this->_credentials,
      'https://example.test',
      timeout: ApiClient::MAX_TIMEOUT_SECONDS,
      transport: $transport,
      connect_timeout: 0.000001
    );
    $client->get('/ping');

    self::assertSame(ApiClient::MAX_TIMEOUT_SECONDS, $transport->requests[0]->getTotalTimeout());
    self::assertSame(0.000001, $transport->requests[0]->getConnectTimeout());
  }

  public function testIpv6HostsAreNormalizedWithoutDoubleBrackets():void {
    $https = new ApiClient(
      $this->_credentials,
      'https://[2001:db8::1]:8443/api',
      transport: new FakeTransport()
    );
    self::assertSame('https://[2001:db8::1]:8443/api', $https->getBaseUrl());

    $local_transport = new FakeTransport();
    $local = new ApiClient(
      $this->_credentials,
      'http://[::1]:8080',
      transport: $local_transport,
      allow_http_for_local_development: true
    );
    $local->get('/ping');
    self::assertSame('http://[::1]:8080/ping', $local_transport->requests[0]->getUrl());

    $this->expectException(\InvalidArgumentException::class);
    new ApiClient(
      $this->_credentials,
      'http://[::1]:8080',
      transport: new FakeTransport()
    );
  }

  public function testEachPhysicalRequestGetsANewNonce():void {
    $transport = new FakeTransport();
    $client = new ApiClient($this->_credentials, 'https://example.test', transport: $transport);
    $client->get('/ping');
    $client->get('/ping');

    self::assertNotSame(
      $transport->requests[0]->getHeaders()[Signer::HEADER_NONCE],
      $transport->requests[1]->getHeaders()[Signer::HEADER_NONCE]
    );
  }
}
