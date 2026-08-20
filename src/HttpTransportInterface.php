<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client;

interface HttpTransportInterface {

  /**
   * Send one physical HTTP request attempt.
   *
   * Implementations must not automatically retry a signed request.
   */
  public function send(HttpRequest $request):ApiResponse;
}
