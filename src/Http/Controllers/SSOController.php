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
    $response = Http::asForm()->post(
      env('SSO_HOST') . '/oauth/token',
      [
        'grant_type' => 'authorization_code',
        'client_id' => env('SSO_CLIENT_ID'),
        'client_secret' => env('SSO_CLIENT_SECRET'),
        'redirect_uri' => env('SSO_CLIENT_CALLBACK'),
        'code' => $request->code
      ]
    );
    $now = \Carbon\Carbon::now()->toIso8601String();
    session(['auth_at' => $now]);
    $request->session()->put($response->json());
    $access_token = $request->session()->get('access_token');

    $response = Http::withHeaders([
      'Accept' => 'application/json',
      'Authorization' => 'Bearer ' . $access_token
    ])->get(env('SSO_HOST') . '/api/user');
    $user = $response->json();
    $request->session()->put('user', $user);

    if ($response->status() !== 200) {
      $request->session()->invalidate();
      $request->session()->regenerateToken();
      return response()->json(['message' => 'Unauthorized'], 403);
    }

    $responseTokens = Http::withHeaders([
      'Accept' => 'application/json',
      'Authorization' => 'Bearer ' . $access_token
    ])->get(env('SSO_HOST') . '/api/tokens');

    if ($responseTokens->status() !== 200) {
      $request->session()->invalidate();
      $request->session()->regenerateToken();
      return response()->json(['message' => 'Failed to retrieve tokens from SSO Server'], $responseTokens->status());
    }

    $tokens = $responseTokens->json();
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
      return response()->json(['message' => 'You have been successfully logged out']);
    } else {
      return response()->json(['message' => 'Unauthorized'], 403);
    }
  }
}
