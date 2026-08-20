<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client\Tests;

use PHPUnit\Framework\TestCase;
use TimeFrontiers\Auth\Client\Credentials;

final class CredentialsTest extends TestCase {

  public function testCredentialsAreValidatedAndNotTrimmed():void {
    $this->expectException(\InvalidArgumentException::class);
    new Credentials(' app ', 'selector', 'secret');
  }

  public function testArrayValuesRejectNonScalarCredentialMaterial():void {
    try {
      Credentials::fromArray([
        'app_id' => ['not', 'a', 'string'],
        'public_key' => 'selector',
        'secret_key' => 'secret-do-not-print',
      ]);
      self::fail('Invalid credentials should throw.');
    } catch (\InvalidArgumentException $exception) {
      self::assertStringNotContainsString('secret-do-not-print', $exception->getMessage());
      self::assertStringNotContainsString('Array', $exception->getMessage());
    }
  }

  public function testDebugOutputRedactsSecretAndSerializationIsDenied():void {
    $credentials = new Credentials('app-1', 'selector-1', 'secret-do-not-print');
    $debug = \print_r($credentials, true);

    self::assertStringContainsString('[REDACTED]', $debug);
    self::assertStringNotContainsString('secret-do-not-print', $debug);

    $this->expectException(\RuntimeException::class);
    \serialize($credentials);
  }

  public function testSecretParametersAreMarkedSensitive():void {
    $constructor = new \ReflectionMethod(Credentials::class, '__construct');
    $secret = $constructor->getParameters()[2];

    self::assertCount(1, $secret->getAttributes(\SensitiveParameter::class));
  }
}
