<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client\Tests;

use PHPUnit\Framework\TestCase;
use TimeFrontiers\Auth\Client\{Credentials, Signer};

final class SignerTest extends TestCase {

  private Credentials $_credentials;

  protected function setUp():void {
    $this->_credentials = new Credentials('app-1', 'selector-1', 'test-secret');
  }

  public function testEmptyBodyAndZeroBodyHaveDifferentIntegritySemantics():void {
    $timestamp = 1700000000;
    $nonce = '00112233445566778899aabbccddeeff';
    $empty = Signer::generateHeaders($this->_credentials, 'POST', '/value', '', $timestamp, $nonce);
    $zero = Signer::generateHeaders($this->_credentials, 'POST', '/value', '0', $timestamp, $nonce);

    self::assertArrayNotHasKey(Signer::HEADER_BODY_HASH, $empty);
    self::assertSame(Signer::hashBody('0'), $zero[Signer::HEADER_BODY_HASH]);
    self::assertNotSame($empty[Signer::HEADER_SIGNATURE], $zero[Signer::HEADER_SIGNATURE]);
  }

  public function testPublicKeySelectorIsSentButNotCanonical():void {
    $timestamp = 1700000000;
    $nonce = '00112233445566778899aabbccddeeff';
    $headers = Signer::generateHeaders($this->_credentials, 'GET', '/ping', '', $timestamp, $nonce);
    $canonical = Signer::buildCanonicalString('app-1', 'GET', '/ping', $timestamp, $nonce);

    self::assertSame('selector-1', $headers[Signer::HEADER_PUBLIC_KEY]);
    self::assertStringNotContainsString('selector-1', $canonical);
  }

  public function testEveryGeneratedNonceIsExactLowercaseHexAndUnique():void {
    $first = Signer::generateNonce();
    $second = Signer::generateNonce();

    self::assertMatchesRegularExpression('/\A[a-f0-9]{32}\z/D', $first);
    self::assertNotSame($first, $second);
  }

  public function testInvalidSignatureShapeReturnsFalse():void {
    self::assertFalse(Signer::verifySignature(
      'NOT-HEX',
      'test-secret',
      'app-1',
      'GET',
      '/ping',
      1700000000,
      '00112233445566778899aabbccddeeff'
    ));
  }

  public function testInvalidRequestTargetsAndProtocolInputsAreRejected():void {
    foreach (['https://example.test/path', '//example.test/path', '/path#fragment', "/path\r\nvalue", '/space here'] as $target) {
      try {
        Signer::validateRequestTarget($target);
        self::fail("Target should be rejected: {$target}");
      } catch (\InvalidArgumentException) {
        self::addToAssertionCount(1);
      }
    }

    $this->expectException(\InvalidArgumentException::class);
    Signer::buildCanonicalString(
      'app-1',
      "GET\nPOST",
      '/ping',
      1700000000,
      '00112233445566778899aabbccddeeff'
    );
  }
}
