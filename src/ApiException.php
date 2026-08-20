<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client;

/**
 * Exception for local transport failures and non-success API responses.
 */
class ApiException extends \Exception {

  private string $_error_code;
  private ?ApiResponse $_response;

  public function __construct(
    string $message,
    string $error_code = 'API_ERROR',
    ?ApiResponse $response = null,
    ?\Throwable $previous = null
  ) {
    $this->_error_code = $error_code;
    $this->_response = $response;
    parent::__construct($message, 0, $previous);
  }

  public function getErrorCode():string {
    return $this->_error_code;
  }

  public function getResponse():?ApiResponse {
    return $this->_response;
  }

  public function getStatusCode():?int {
    return $this->_response?->getStatusCode();
  }
}
