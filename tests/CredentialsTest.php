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
    $credentials = Credentials::forSelector('app-1', 'selector-1', 'secret-do-not-print');
    $debug = \print_r($credentials, true);

    self::assertStringContainsString('[REDACTED]', $debug);
    self::assertStringNotContainsString('secret-do-not-print', $debug);

    $this->expectException(\RuntimeException::class);
    \serialize($credentials);
  }

  public function testPublicSelectorArrayKeyIsPreferredOverLegacyAppId():void {
    $credentials = Credentials::fromArray([
      'credential_selector' => '1234',
      'app_id' => '123',
      'public_key' => 'selector-1',
      'secret_key' => 'secret-do-not-print',
    ]);

    self::assertSame('1234', $credentials->getCredentialSelector());
    self::assertFalse($credentials->usesLegacyAppId());
  }

  public function testLegacyAppIdRequiresAnExplicitCanonicalNumericInput():void {
    $credentials = Credentials::fromArray([
      'app_id' => '123',
      'public_key' => 'selector-1',
      'secret_key' => 'secret-do-not-print',
    ]);

    self::assertSame('123', $credentials->getCredentialSelector());
    self::assertTrue($credentials->usesLegacyAppId());

    $this->expectException(\InvalidArgumentException::class);
    Credentials::forLegacyAppId('analytics.app', 'selector-1', 'secret-do-not-print');
  }

  public function testPublicSelectorUsesTheServerProtocolGrammar():void {
    foreach (['Analytics.app', 'analytics app', 'analytics/app', '_analytics'] as $selector) {
      try {
        Credentials::forSelector($selector, 'selector-1', 'secret-do-not-print');
        self::fail("Invalid public selector should be rejected: {$selector}");
      } catch (\InvalidArgumentException) {
        self::addToAssertionCount(1);
      }
    }

    $credentials = Credentials::forSelector('1234', 'selector-1', 'secret-do-not-print');
    self::assertSame('1234', $credentials->getCredentialSelector());
  }

  public function testNumericEnvironmentSelectorIsNotInferredAsLegacy():void {
    $values = [
      'TF_AUTH_SELECTOR_TEST_CREDENTIAL_SELECTOR' => '1234',
      'TF_AUTH_SELECTOR_TEST_APP_ID' => '99',
      'TF_AUTH_SELECTOR_TEST_PUBLIC_KEY' => 'selector-1',
      'TF_AUTH_SELECTOR_TEST_SECRET_KEY' => 'secret-do-not-print',
    ];
    $previous = [];
    foreach ($values as $name => $value) {
      $previous[$name] = \getenv($name);
      \putenv("{$name}={$value}");
    }

    try {
      $credentials = Credentials::fromEnv('TF_AUTH_SELECTOR_TEST');
      self::assertSame('1234', $credentials->getCredentialSelector());
      self::assertFalse($credentials->usesLegacyAppId());
    } finally {
      foreach ($previous as $name => $value) {
        \putenv($value === false ? $name : "{$name}={$value}");
      }
    }
  }

  public function testSecretParametersAreMarkedSensitive():void {
    $constructor = new \ReflectionMethod(Credentials::class, '__construct');
    $secret = $constructor->getParameters()[2];

    self::assertCount(1, $secret->getAttributes(\SensitiveParameter::class));
  }
}
