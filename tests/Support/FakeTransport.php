<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client\Tests\Support;

use TimeFrontiers\Auth\Client\{ApiResponse, HttpRequest, HttpTransportInterface};

final class FakeTransport implements HttpTransportInterface {

  /** @var list<HttpRequest> */
  public array $requests = [];

  /** @var list<ApiResponse> */
  private array $_responses;

  /**
   * @param list<ApiResponse> $responses
   */
  public function __construct(array $responses = []) {
    $this->_responses = $responses;
  }

  public function send(HttpRequest $request):ApiResponse {
    $this->requests[] = $request;
    return \array_shift($this->_responses) ?? new ApiResponse(200, [], '{}');
  }
}
