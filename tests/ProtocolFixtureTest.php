<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client\Tests;

use PHPUnit\Framework\TestCase;
use TimeFrontiers\Auth\Client\Signer;

final class ProtocolFixtureTest extends TestCase {

  public function testSharedProtocolVectors():void {
    $json = \file_get_contents(__DIR__ . '/../fixtures/protocol-v1.1.json');
    self::assertIsString($json);

    /**
     * @var array{
     *   app_id: string,
     *   hmac_test_key: string,
     *   timestamp: int,
     *   nonce: string,
     *   cases: list<array{
     *     name: string,
     *     method: string,
     *     request_target: string,
     *     body: string,
     *     body_hash: string,
     *     canonical: string,
     *     signature: string,
     *     valid: bool
     *   }>
     * } $fixture
     */
    $fixture = \json_decode($json, true, 512, \JSON_THROW_ON_ERROR);

    foreach ($fixture['cases'] as $case) {
      $body_hash = $case['body'] !== '' ? Signer::hashBody($case['body']) : '';
      self::assertSame($case['body_hash'], $body_hash, $case['name']);

      $canonical = Signer::buildCanonicalString(
        $fixture['app_id'],
        $case['method'],
        $case['request_target'],
        $fixture['timestamp'],
        $fixture['nonce'],
        $body_hash
      );
      self::assertSame($case['canonical'], $canonical, $case['name']);

      $computed = Signer::sign(
        $fixture['hmac_test_key'],
        $fixture['app_id'],
        $case['method'],
        $case['request_target'],
        $fixture['timestamp'],
        $fixture['nonce'],
        $body_hash
      );

      if ($case['valid']) {
        self::assertSame($case['signature'], $computed, $case['name']);
      } else {
        self::assertNotSame($case['signature'], $computed, $case['name']);
      }

      self::assertSame($case['valid'], Signer::verifySignature(
        $case['signature'],
        $fixture['hmac_test_key'],
        $fixture['app_id'],
        $case['method'],
        $case['request_target'],
        $fixture['timestamp'],
        $fixture['nonce'],
        $body_hash
      ), $case['name']);
    }
  }
}
