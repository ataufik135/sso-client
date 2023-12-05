<?php

namespace TaufikT\SsoClient;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Session;

class OAuthClient
{
  private $host;
  private $clientId;
  private $clientSecret;
  private $redirectUri;

  public function __construct()
  {
    $this->host = env('SSO_HOST');
    $this->clientId = env('SSO_CLIENT_ID');
    $this->clientSecret = env('SSO_CLIENT_SECRET');
    $this->redirectUri = env('SSO_CLIENT_CALLBACK');
  }

  public function reset()
  {
    session()->invalidate();
    session()->regenerateToken();
  }

  public function storeToken($data)
  {
    session(['auth_at' => \Carbon\Carbon::now()->toIso8601String()]);
    session()->put($data);
  }

  public function storeUser($data)
  {
    session()->put('user', $data);
  }

  public function requestToken($code)
  {
    try {
      $response = Http::withoutVerifying()->acceptJson()->asForm()->post(
        $this->host . '/oauth/token',
        [
          'grant_type' => 'authorization_code',
          'client_id' => $this->clientId,
          'client_secret' => $this->clientSecret,
          'redirect_uri' => $this->redirectUri,
          'code' => $code
        ]
      );

      return $response->json();
    } catch (\Exception $e) {
      //
    }
  }

  public function refreshToken()
  {
    $refresh_token = session()->get('refresh_token');
    if (!$refresh_token) {
      $this->reset();
    }

    try {
      $response = Http::withoutVerifying()->acceptJson()->asForm()->post(
        $this->host . '/oauth/token',
        [
          'grant_type' => 'refresh_token',
          'refresh_token' => $refresh_token,
          'client_id' => $this->clientId,
          'client_secret' => $this->clientSecret,
          'scope' => env('SSO_SCOPES'),
        ]
      );

      return $response->json();
    } catch (\Exception $e) {
      //
    }
  }

  public function isTokenExpired()
  {
    $access_token = session()->get('access_token');
    if (!$access_token) {
      $this->reset();
    }

    $authAt = session()->get('auth_at');
    $expiresIn = session()->get('expires_in');

    if ($authAt === null || $expiresIn === null) {
      return true;
    }

    return \Carbon\Carbon::now()->gte(\Carbon\Carbon::parse($authAt)->addSeconds($expiresIn));
  }

  public function isTokenDuplicate()
  {
    $access_token = session()->get('access_token');
    if (!$access_token) {
      $this->reset();
    }

    try {
      $response = Http::withoutVerifying()->acceptJson()->withHeaders([
        'Authorization' => 'Bearer ' . $access_token
      ])->get($this->host . '/api/tokens');

      $tokens = $response->json();
    } catch (\Exception $e) {
      $this->reset();
    }

    $groupedData = collect($tokens)->groupBy('client_id');
    $duplicates = $groupedData->filter(function ($items) {
      return $items->count() > 1;
    });

    return $duplicates->isNotEmpty() ? true : false;
  }

  public function getUserInfo()
  {
    $access_token = session()->get('access_token');
    if (!$access_token) {
      $this->reset();
    }

    try {
      $response = Http::withoutVerifying()->acceptJson()->withHeaders([
        'Authorization' => 'Bearer ' . $access_token
      ])->get($this->host . '/api/user');

      return $response->json();
    } catch (\Exception $e) {
      $this->reset();
    }
  }

  public function validateToken()
  {
    $access_token = session()->get('access_token');
    if (!$access_token) {
      $this->reset();
    }

    if ($this->isTokenExpired()) {
      if ($refreshToken = $this->refreshToken()) {
        $this->storeToken($refreshToken);
      }
    }

    if ($getUser = $this->getUserInfo()) {
      $user = session()->get('user');
      if ($user['sessionId'] !== $getUser['sessionId']) {
        $this->reset();
      }

      session()->forget('user');
      $this->storeUser($getUser);

      return true;
    }

    return false;
  }

  public function logout($token)
  {
    $token = base64_decode($token);

    $key = 'tPhW82l0s2mV8f?_(ZAz[&Aq_a1&_3}S';

    $secret = new \Illuminate\Encryption\Encrypter($key, 'AES-256-CBC');
    $decrypt = $secret->decrypt($token);

    if (isset($decrypt) && $this->destroySessionById($decrypt)) {
      return true;
    } else {
      return false;
    }
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
}
