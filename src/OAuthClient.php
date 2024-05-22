<?php

namespace TaufikT\SsoClient;

use Carbon\Carbon;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Session;

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

  public function storeToken($data)
  {
    Session::put(['auth_at' => Carbon::now()->toIso8601String()]);
    Session::put($data);
  }

  public function storeUser($data)
  {
    Session::put('user', $data);
  }

  public function requestToken($code, $codeVerifier, $requestIp)
  {
    $response = Http::withoutVerifying()->withHeaders([
      'X-Forwarded-For' => $requestIp,
    ])->acceptJson()->asForm()->post(
      $this->host . '/oauth/token',
      [
        'grant_type' => 'authorization_code',
        'client_id' => $this->clientId,
        'client_secret' => $this->clientSecret,
        'redirect_uri' => $this->redirectUri,
        'code_verifier' => $codeVerifier,
        'code' => $code
      ]
    );

    return $response->json();
  }

  public function refreshToken()
  {
    $refresh_token = Session::get('refresh_token');
    if (!$refresh_token) {
      return redirect($this->clientOrigin);
    }

    $response = Http::withoutVerifying()->acceptJson()->asForm()->post(
      $this->host . '/oauth/token',
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

  public function isTokenExpired()
  {
    $authAt = Session::get('auth_at');
    $expiresIn = Session::get('expires_in');

    if ($authAt === null || $expiresIn === null) {
      return true;
    }

    return Carbon::now()->gte(Carbon::parse($authAt)->addSeconds($expiresIn));
  }

  public function isTokenDuplicate()
  {
    $access_token = Session::get('access_token');
    if (!$access_token) {
      return redirect($this->clientOrigin);
    }

    $response = Http::withoutVerifying()->acceptJson()->withHeaders([
      'Authorization' => 'Bearer ' . $access_token
    ])->get($this->host . '/api/tokens');

    $tokens = $response->json();

    $groupedData = collect($tokens)->groupBy('client_id');
    $duplicates = $groupedData->filter(function ($items) {
      return $items->count() > 1;
    });

    return $duplicates->isNotEmpty() ? true : false;
  }

  public function getUserInfo()
  {
    $access_token = Session::get('access_token');
    if (!$access_token) {
      return redirect($this->clientOrigin);
    }

    $response = Http::withoutVerifying()->acceptJson()->withHeaders([
      'Authorization' => 'Bearer ' . $access_token
    ])->get($this->host . '/api/user');

    return $response->json();
  }

  public function validateToken()
  {
    if (!$this->isTokenExpired()) {
      return true;
    }

    if ($refreshToken = $this->refreshToken()) {
      $this->storeToken($refreshToken);
    }

    if ($getUser = $this->getUserInfo()) {
      $user = Session::get('user');
      if ($user['sessionId'] !== $getUser['sessionId']) {
        return redirect($this->logoutUri);
      }

      Session::forget('user');
      $this->storeUser($getUser);
      return true;
    }
    return false;
  }

  public function logout($token)
  {
    $token = base64_decode($token);

    $key = Config::get('sso.key');
    $encrypt = new \Illuminate\Encryption\Encrypter($key, 'AES-256-CBC');
    $decrypted = $encrypt->decrypt($token);

    if (isset($decrypted) && $this->destroySessionById($decrypted)) {
      return true;
    }
    return false;
  }

  private function destroySessionById($id)
  {
    $sessionPath = storage_path('framework' . DIRECTORY_SEPARATOR . 'sessions');
    $sessionFiles = scandir($sessionPath);

    foreach ($sessionFiles as $file) {
      if ($file !== '.' && $file !== '..') {
        $sessionData = file_get_contents($sessionPath . DIRECTORY_SEPARATOR . $file);

        if (strpos($sessionData, $id) !== false) {
          $sessionId = pathinfo($file, PATHINFO_FILENAME);
          Session::getHandler()->destroy($sessionId);
        }
      }
    }

    return true;
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
