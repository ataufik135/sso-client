<?php

namespace TaufikT\SsoClient;

use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
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

  public function __construct()
  {
    $this->host = Config::get('sso.host');
    $this->logoutUri = Config::get('sso.host_logout');
    $this->clientId = Config::get('sso.client_id');
    $this->clientSecret = Config::get(('sso.client_secret'));
    $this->redirectUri = Config::get('sso.client_callback');
    $this->clientOrigin = Config::get('sso.client_origin');
    $this->scopes = Config::get('sso.scopes');
  }

  public function addAuthUser($userId, $sessionId)
  {
    $users = Cache::get('authenticated-users');

    $users[$userId] = ['sessionId' => $sessionId];
    Cache::forever('authenticated-users', $users);
  }
  public function removeAuthUser($userId)
  {
    $users = cache::get('authenticated-users');
    unset($users[$userId]);
    Cache::forever('authenticated-users', $users);
  }
  public function countAuthUser()
  {
    $users = cache::get('authenticated-users');
    return count($users);
  }
  public function getSessionIdAuthUser($userId)
  {
    $sessionId = cache::get('authenticated-users')[$userId]['sessionId'];
    return $sessionId;
  }
  public function getAllUserIdAuthUser()
  {
    return array_keys(cache::get('authenticated-users'));
  }
  public function checkAuthUser($userId)
  {
    return isset(Cache::get('authenticated-users')[$userId]);
  }
  public function updateOnlineUsers($data)
  {
    $httpClient = new Client([
      'http_errors' => false,
      'verify' => false
    ]);
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
  }

  public function storeToken($data)
  {
    Session::put($data);
  }
  public function requestToken($code, $codeVerifier, $requestIp)
  {
    $response = Http::withoutVerifying()->withHeaders([
      'X-Forwarded-For' => $requestIp,
    ])->acceptJson()->asForm()->post(
      $this->host . '/api/oauth/token',
      [
        'grant_type' => 'authorization_code',
        'client_id' => $this->clientId,
        'client_secret' => $this->clientSecret,
        'redirect_uri' => $this->redirectUri,
        'code_verifier' => $codeVerifier,
        'code' => $code
      ]
    );

    if ($response->status() === 409) {
      return redirect($this->logoutUri);
    }

    $this->storeToken($response->json());
    if ($response->status() === 403) {
      abort(403);
    }
  }

  public function refreshToken()
  {
    $refresh_token = Session::get('refresh_token');
    if (!$refresh_token) {
      return redirect($this->clientOrigin);
    }

    $response = Http::withoutVerifying()->acceptJson()->asForm()->post(
      $this->host . '/api/oauth/token',
      [
        'grant_type' => 'refresh_token',
        'refresh_token' => $refresh_token,
        'client_id' => $this->clientId,
        'client_secret' => $this->clientSecret,
        'scope' => $this->scopes,
      ]
    );

    return $response->json();
  }

  public function logout($token)
  {
    $token = base64_decode($token);

    $key = Config::get('sso.key');
    $encrypt = new \Illuminate\Encryption\Encrypter($key, 'AES-256-CBC');
    $decrypted = $encrypt->decrypt($token);

    $this->destroySessionById($decrypted);
  }

  private function destroySessionById($userId)
  {
    $sessionId = $this->getSessionIdAuthUser($userId);
    $this->removeAuthUser($userId);
    Session::getHandler()->destroy($sessionId);
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
