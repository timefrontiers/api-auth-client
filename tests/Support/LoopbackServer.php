<?php

declare(strict_types=1);

namespace TimeFrontiers\Auth\Client\Tests\Support;

/**
 * One-request raw TCP server used to observe the physical HTTP request line.
 */
final class LoopbackServer {

  private string $_state_file;
  private int $_port;

  /** @var resource */
  private $_process;

  /** @var array<int, resource> */
  private array $_pipes;

  /**
   * @param resource $process
   * @param array<int, resource> $pipes
   */
  private function __construct(string $state_file, int $port, $process, array $pipes) {
    $this->_state_file = $state_file;
    $this->_port = $port;
    $this->_process = $process;
    $this->_pipes = $pipes;
  }

  public static function start():self {
    $state_file = \tempnam(\sys_get_temp_dir(), 'api-auth-client-');
    if ($state_file === false) {
      throw new \RuntimeException('Could not create loopback server state file.');
    }

    $null_device = \PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null';
    $descriptors = [
      0 => ['file', $null_device, 'r'],
      1 => ['pipe', 'w'],
      2 => ['pipe', 'w'],
    ];
    $process = \proc_open(
      [\PHP_BINARY, __FILE__, 'serve', $state_file],
      $descriptors,
      $pipes,
      \dirname(__DIR__, 2)
    );

    if (!\is_resource($process)) {
      @\unlink($state_file);
      throw new \RuntimeException('Could not start loopback server process.');
    }

    /** @var array<int, resource> $pipes */
    $deadline = \microtime(true) + 5.0;
    do {
      $state = self::_readState($state_file);
      if (isset($state['port']) && \is_int($state['port']) && $state['port'] > 0) {
        return new self($state_file, $state['port'], $process, $pipes);
      }
      \usleep(10000);
    } while (\microtime(true) < $deadline);

    foreach ($pipes as $pipe) {
      \fclose($pipe);
    }
    \proc_terminate($process);
    \proc_close($process);
    @\unlink($state_file);
    throw new \RuntimeException('Loopback server did not become ready.');
  }

  public function getPort():int {
    return $this->_port;
  }

  /**
   * @return array{port: int, request_line: string, request_target: string, body: string, header_names: list<string>}
   */
  public function awaitRequest():array {
    $deadline = \microtime(true) + 5.0;
    do {
      $state = self::_readState($this->_state_file);
      if (isset($state['request_line'])) {
        /** @var array{port: int, request_line: string, request_target: string, body: string, header_names: list<string>} $state */
        return $state;
      }
      \usleep(10000);
    } while (\microtime(true) < $deadline);

    throw new \RuntimeException('Loopback server did not record a request.');
  }

  public function stop():void {
    foreach ($this->_pipes as $pipe) {
      if (\is_resource($pipe)) {
        \fclose($pipe);
      }
    }
    $this->_pipes = [];

    if (\is_resource($this->_process)) {
      $status = \proc_get_status($this->_process);
      if ($status['running']) {
        \proc_terminate($this->_process);
      }
      \proc_close($this->_process);
    }

    if (\is_file($this->_state_file)) {
      @\unlink($this->_state_file);
    }
  }

  public static function serve(string $state_file):int {
    $errno = 0;
    $error = '';
    $server = \stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    if ($server === false) {
      return 2;
    }

    $address = \stream_socket_get_name($server, false);
    if ($address === false || !\str_contains($address, ':')) {
      \fclose($server);
      return 3;
    }
    $port = (int) \substr($address, (int) \strrpos($address, ':') + 1);
    self::_writeState($state_file, ['port' => $port]);

    $connection = \stream_socket_accept($server, 10);
    if ($connection === false) {
      \fclose($server);
      return 4;
    }

    $request_line = \fgets($connection);
    if ($request_line === false) {
      \fclose($connection);
      \fclose($server);
      return 5;
    }
    $request_line = \rtrim($request_line, "\r\n");

    $header_names = [];
    $content_length = 0;
    while (($line = \fgets($connection)) !== false) {
      $line = \rtrim($line, "\r\n");
      if ($line === '') {
        break;
      }
      if (!\str_contains($line, ':')) {
        continue;
      }
      [$name, $value] = \explode(':', $line, 2);
      $name = \strtolower(\trim($name));
      $header_names[] = $name;
      if ($name === 'content-length') {
        $content_length = (int) \trim($value);
      }
    }

    $body = '';
    while (\strlen($body) < $content_length) {
      $remaining = $content_length - \strlen($body);
      if ($remaining <= 0) {
        break;
      }
      $chunk = \fread($connection, $remaining);
      if ($chunk === false || $chunk === '') {
        break;
      }
      $body .= $chunk;
    }

    $parts = \explode(' ', $request_line, 3);
    $request_target = $parts[1] ?? '';
    self::_writeState($state_file, [
      'port' => $port,
      'request_line' => $request_line,
      'request_target' => $request_target,
      'body' => $body,
      'header_names' => $header_names,
    ]);

    $response = "HTTP/1.1 100 Continue\r\nInterim: yes\r\n\r\n"
      . "HTTP/1.1 201 Created\r\n"
      . "Set-Cookie: a=1\r\n"
      . "Set-Cookie: b=2\r\n"
      . "X-Final: yes\r\n"
      . "Content-Length: 2\r\n"
      . "Connection: close\r\n\r\nOK";
    \fwrite($connection, $response);
    \fclose($connection);
    \fclose($server);

    return 0;
  }

  /**
   * @return array<string, mixed>
   */
  private static function _readState(string $state_file):array {
    $json = @\file_get_contents($state_file);
    if (!\is_string($json) || $json === '') {
      return [];
    }

    try {
      $state = \json_decode($json, true, 512, \JSON_THROW_ON_ERROR);
      if (!\is_array($state)) {
        return [];
      }

      $normalized = [];
      foreach ($state as $key => $value) {
        if (\is_string($key)) {
          $normalized[$key] = $value;
        }
      }
      return $normalized;
    } catch (\JsonException) {
      return [];
    }
  }

  /**
   * @param array<string, mixed> $state
   */
  private static function _writeState(string $state_file, array $state):void {
    \file_put_contents($state_file, \json_encode($state, \JSON_THROW_ON_ERROR), \LOCK_EX);
  }
}

if (($argv[1] ?? null) === 'serve') {
  exit(LoopbackServer::serve((string) ($argv[2] ?? '')));
}
