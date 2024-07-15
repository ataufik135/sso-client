<?php

namespace TaufikT\SsoClient;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Session;
use GuzzleHttp\Client;
use GuzzleHttp\Promise;

class OAuthClient
{
  protected $host;
  protected $logoutUri;
  protected $clientId;
  protected $clientSecret;
  protected $redirectUri;
  protected $clientOrigin;
  protected $scopes;
  protected $version;
  protected $sslVerify;

  public function __construct()
  {
    $this->host = Config::get('sso.host');
    $this->logoutUri = Config::get('sso.host_logout');
    $this->clientId = Config::get('sso.client_id');
    $this->clientSecret = Config::get(('sso.client_secret'));
    $this->redirectUri = Config::get('sso.client_callback');
    $this->clientOrigin = Config::get('sso.client_origin');
    $this->scopes = Config::get('sso.scopes');
    $this->version = Config::get('sso.version');
    $this->sslVerify = false;
  }

  public function addUnauthUser($userId, $clientSessionId)
  {
    $users = Cache::get('unauthenticated-users');

    $users[$userId] = [
      'clientSessionId' => $clientSessionId
    ];
    Cache::forever('unauthenticated-users', $users);
  }
  public function removeUnauthUser($userId)
  {
    $users = Cache::get('unauthenticated-users');
    unset($users[$userId]);
    Cache::forever('unauthenticated-users', $users);
  }
  public function addAuthUser($userId, $sessionId, $clientSessionId)
  {
    $users = Cache::get('authenticated-users');

    $users[$userId] = [
      'sessionId' => $sessionId,
      'clientSessionId' => $clientSessionId
    ];
    Cache::forever('authenticated-users', $users);
  }
  public function removeAuthUser($userId)
  {
    $users = Cache::get('authenticated-users');
    unset($users[$userId]);
    Cache::forever('authenticated-users', $users);
  }
  public function countAuthUser()
  {
    $users = Cache::get('authenticated-users');
    return count($users);
  }
  public function getClientSessionIdUnauthUser($userId)
  {
    $clientSessionId = Cache::get('unauthenticated-users')[$userId]['clientSessionId'];
    return $clientSessionId;
  }
  public function getClientSessionIdAuthUser($userId)
  {
    $clientSessionId = Cache::get('authenticated-users')[$userId]['clientSessionId'];
    return $clientSessionId;
  }
  public function getAllUserIdAuthUser()
  {
    return array_keys(Cache::get('authenticated-users'));
  }
  public function checkUnauthUser($userId)
  {
    return isset(Cache::get('unauthenticated-users')[$userId]);
  }
  public function checkAuthUser($userId)
  {
    return isset(Cache::get('authenticated-users')[$userId]);
  }
  public function updateOnlineUsers($data)
  {
    $httpClient = new Client([
      'http_errors' => false,
      'verify' => $this->sslVerify,
    ]);

    try {
      $promises = $httpClient->postAsync(
        $this->host . '/api/online-users',
        [
          'headers' => [
            'Accept' => 'application/json',
            'client-id' => $this->clientId
          ],
          'form_params' => ['online_users' => $data]
        ]

      );

      Promise\Utils::settle($promises)->wait();
    } catch (\Exception $e) {
      //throw $e;
    }
  }

  public function storeToken($data)
  {
    Session::put($data);
  }
  public function requestToken($code, $codeVerifier, $requestIp)
  {
    $httpClient = new Client([
      'verify' => $this->sslVerify,
    ]);

    $response = $httpClient->post($this->host . '/api/oauth/token', [
      'headers' => [
        'Accept' => 'application/json',
        'X-Forwarded-For' => $requestIp,
        'client-version' => $this->version,
      ],
      'form_params' => [
        'grant_type' => 'authorization_code',
        'client_id' => $this->clientId,
        'client_secret' => $this->clientSecret,
        'redirect_uri' => $this->redirectUri,
        'code_verifier' => $codeVerifier,
        'code' => $code
      ]
    ]);

    if ($response->getStatusCode() === 409) {
      return redirect($this->logoutUri);
    }

    $this->storeToken(json_decode($response->getBody(), true));
    return $response;
  }

  public function logout($token)
  {
    $jwtToken = jwtDecrypt($token);
    $this->destroySessionById(base64_decode($jwtToken->id));
  }

  private function destroySessionById($userId)
  {
    if ($this->checkAuthUser($userId)) {
      $clientSessionId = $this->getClientSessionIdAuthUser($userId);
      $this->removeAuthUser($userId);
    } else {
      $clientSessionId = $this->getClientSessionIdUnauthUser($userId);
      $this->removeUnauthUser($userId);
    }
    Session::getHandler()->destroy($clientSessionId);
  }

  public function host()
  {
    return $this->host;
  }
  public function logoutUri()
  {
    return $this->logoutUri;
  }
  public function clientId()
  {
    return $this->clientId;
  }
  public function clientSecret()
  {
    return $this->clientSecret;
  }
  public function redirectUri()
  {
    return $this->redirectUri;
  }
  public function clientOrigin()
  {
    return $this->clientOrigin;
  }
  public function scopes()
  {
    return $this->scopes;
  }
}
