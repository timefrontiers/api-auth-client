<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client;

/**
 * Exception for API request failures.
 */
class ApiException extends \Exception {

  private string $_error_code;
  private ?ApiResponse $_response;

  public function __construct(string $message, string $error_code = 'API_ERROR', ?ApiResponse $response = null) {
    $this->_error_code = $error_code;
    $this->_response = $response;
    parent::__construct($message);
  }

  /**
   * Get the error code from the API.
   */
  public function getErrorCode():string {
    return $this->_error_code;
  }

  /**
   * Get the full response object.
   */
  public function getResponse():?ApiResponse {
    return $this->_response;
  }

  /**
   * Get the HTTP status code.
   */
  public function getStatusCode():?int {
    return $this->_response?->getStatusCode();
  }
}
