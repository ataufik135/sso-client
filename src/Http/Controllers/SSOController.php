<?php

namespace TaufikT\SsoClient\Http\Controllers;

use Illuminate\Http\Request;
use App\Providers\RouteServiceProvider;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class SSOController
{
  public function redirect(Request $request)
  {
    if (empty(env('SSO_CLIENT_ID')) || empty(env('SSO_CLIENT_SECRET')) || empty(env('SSO_CLIENT_CALLBACK')) || empty(env('SSO_CLIENT_ORIGIN')) || empty(env('SSO_HOST')) || empty(env('SSO_HOST_LOGOUT'))) {
      return 'Please fill SSO fields in env file';
    }

    $request->session()->put('state', $state = Str::random(40));
    $query = http_build_query([
      'client_id' => env('SSO_CLIENT_ID'),
      'redirect_uri' => env('SSO_CLIENT_CALLBACK'),
      'response_type' => 'code',
      //   'prompt' => 'none',
      'scope' => env('SSO_SCOPES'),
      'state' => $state,
    ]);

    return redirect(env('SSO_HOST') . '/oauth/authorize?' . $query);
  }
  public function callback(Request $request)
  {
    $state = $request->session()->pull('state');
    throw_unless(strlen($state) > 0 && $state === $request->state, InvalidArgumentException::class);

    $retryCount = 3;
    $retryDelay = 1;
    $timeout = 15;

    for ($attempt = 1; $attempt <= $retryCount; $attempt++) {
      try {
        $response = Http::withoutVerifying()->timeout($timeout)->asForm()->post(
          env('SSO_HOST') . '/oauth/token',
          [
            'grant_type' => 'authorization_code',
            'client_id' => env('SSO_CLIENT_ID'),
            'client_secret' => env('SSO_CLIENT_SECRET'),
            'redirect_uri' => env('SSO_CLIENT_CALLBACK'),
            'code' => $request->code
          ]
        );

        if ($response->successful()) {
          break;
        }
      } catch (\RequestException $e) {
        if ($attempt < $retryCount) {
          sleep($retryDelay);
        } else {
          return response()->json(['message' => 'Request failed after $retryCount attempts: ' . $e->getMessage()], 408);
        }
      }
    }

    $now = \Carbon\Carbon::now()->toIso8601String();
    session(['auth_at' => $now]);
    $request->session()->put($response->json());
    $access_token = $request->session()->get('access_token');

    for ($attempt = 1; $attempt <= $retryCount; $attempt++) {
      try {
        $response = Http::withoutVerifying()->timeout($timeout)->withHeaders([
          'Accept' => 'application/json',
          'Authorization' => 'Bearer ' . $access_token
        ])->get(env('SSO_HOST') . '/api/user');

        if ($response->successful()) {
          break;
        }
      } catch (\RequestException $e) {
        if ($attempt < $retryCount) {
          sleep($retryDelay);
        } else {
          $request->session()->invalidate();
          $request->session()->regenerateToken();
          return response()->json(['message' => 'Unauthorized'], 403);
        }
      }
    }

    $user = $response->json();
    $request->session()->put('user', $user);

    for ($attempt = 1; $attempt <= $retryCount; $attempt++) {
      try {
        $response = Http::withoutVerifying()->timeout($timeout)->withHeaders([
          'Accept' => 'application/json',
          'Authorization' => 'Bearer ' . $access_token
        ])->get(env('SSO_HOST') . '/api/tokens');

        if ($response->successful()) {
          break;
        }
      } catch (\RequestException $e) {
        if ($attempt < $retryCount) {
          sleep($retryDelay);
        } else {
          $request->session()->invalidate();
          $request->session()->regenerateToken();
          return response()->json(['message' => 'Failed to retrieve tokens from SSO Server'], $response->status());
        }
      }
    }

    $tokens = $response->json();
    $groupedData = collect($tokens)->groupBy('client_id');
    $duplicates = $groupedData->filter(function ($items) {
      return $items->count() > 1;
    });

    if ($duplicates->isNotEmpty()) {
      return redirect(route('oauth2.logout'));
    }

    return redirect(RouteServiceProvider::HOME);
  }

  public function logout(Request $request)
  {
    $request->session()->invalidate();
    $request->session()->regenerateToken();
    return redirect(env('SSO_HOST_LOGOUT'));
  }

  public function handleLogoutNotification(Request $request)
  {
    $token = $request->header('Authorization');
    if (!$token) {
      return response()->json(['message' => 'Unauthorized'], 403);
    }
    $token = base64_decode($token);

    $key = 'tPhW82l0s2mV8f?_(ZAz[&Aq_a1&_3}S';

    $secret = new \Illuminate\Encryption\Encrypter($key, 'AES-256-CBC');
    $decrypt = $secret->decrypt($token);


    if (isset($decrypt)) {
      destroySessionById($decrypt);
      return response()->json(['message' => 'You have been successfully logged out'], 200);
    } else {
      return response()->json(['message' => 'Unauthorized'], 403);
    }
  }
}
