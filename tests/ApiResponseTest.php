<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client\Tests;

use PHPUnit\Framework\TestCase;
use TimeFrontiers\Auth\Client\{ApiException, ApiResponse};

final class ApiResponseTest extends TestCase {

  public function testRepeatedHeadersArePreservedAndConvenienceValueIsCombined():void {
    $response = new ApiResponse(200, [
      'set-cookie' => ['a=1', 'b=2'],
      'content-type' => 'application/json',
    ], '{}');

    self::assertSame(['a=1', 'b=2'], $response->getHeaderValues('Set-Cookie'));
    self::assertSame('a=1, b=2', $response->getHeader('set-cookie'));
    self::assertSame('application/json', $response->getHeaders()['content-type']);
  }

  public function testMalformedAndScalarJsonAreObservable():void {
    $malformed = new ApiResponse(200, [], '{bad');
    self::assertNull($malformed->json());
    self::assertTrue($malformed->hasJsonError());
    self::assertFalse($malformed->isJsonScalar());

    $scalar = new ApiResponse(200, [], '42');
    self::assertNull($scalar->json());
    self::assertFalse($scalar->hasJsonError());
    self::assertTrue($scalar->isJsonScalar());
  }

  public function testRedirectsAndEveryOtherNon2xxResponseThrow():void {
    $response = new ApiResponse(302, ['location' => '/login'], '');
    self::assertTrue($response->isError());

    try {
      $response->throwIfError();
      self::fail('Redirect should throw.');
    } catch (ApiException $exception) {
      self::assertSame('HTTP 302', $exception->getMessage());
      self::assertSame(302, $exception->getStatusCode());
    }
  }

  public function testUntrustedRemoteErrorsAreBoundedAndTypeSafe():void {
    $typed = new ApiResponse(422, [], '{"message":["not","a","string"],"code":123}');
    try {
      $typed->throwIfError();
      self::fail('Error response should throw.');
    } catch (ApiException $exception) {
      self::assertSame('HTTP 422', $exception->getMessage());
      self::assertSame('123', $exception->getErrorCode());
    }

    $oversized_body = \json_encode(['message' => \str_repeat('private-data', 7000)], \JSON_THROW_ON_ERROR);
    $oversized = new ApiResponse(500, [], $oversized_body);
    try {
      $oversized->throwIfError();
      self::fail('Error response should throw.');
    } catch (ApiException $exception) {
      self::assertSame('HTTP 500', $exception->getMessage());
      self::assertStringNotContainsString('private-data', $exception->getMessage());
    }
  }

  public function testToArrayDoesNotExposeBodyOrHeaders():void {
    $response = new ApiResponse(200, ['set-cookie' => 'session=secret'], '{"token":"secret"}');
    $safe = $response->toArray();

    self::assertArrayNotHasKey('body', $safe);
    self::assertArrayNotHasKey('headers', $safe);
    self::assertStringNotContainsString('secret', \json_encode($safe, \JSON_THROW_ON_ERROR));
  }
}
