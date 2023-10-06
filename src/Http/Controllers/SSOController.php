<?php

namespace TaufikT\SsoClient\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class SSOController
{
  public function redirect(Request $request)
  {
    $request->session()->put('state', $state = Str::random(40));
    $query = http_build_query([
      'client_id' => env('SSO_CLIENT_ID'),
      'redirect_uri' => env('SSO_CLIENT_CALLBACK'),
      'response_type' => 'code',
      'scope' => env('SSO_SCOPES'),
      'state' => $state
    ]);
    return redirect(env('SSO_HOST') . '/oauth/authorize?' . $query);
  }
  public function callback(Request $request)
  {
    $state = $request->session()->pull('state');

    throw_unless(strlen($state) > 0 && $state === $request->state, InvalidArgumentException::class);

    $responses = Http::asForm()->post(
      env('SSO_HOST') . '/oauth/token',
      [
        'grant_type' => 'authorization_code',
        'client_id' => env('SSO_CLIENT_ID'),
        'client_secret' => env('SSO_CLIENT_SECRET'),
        'redirect_uri' => env('SSO_CLIENT_CALLBACK'),
        'code' => $request->code
      ]
    );
    $request->session()->put($responses->json());

    $access_token = $request->session()->get('access_token');
    $responses = Http::withHeaders([
      'Accept' => 'application/json',
      'Authorization' => 'Bearer ' . $access_token
    ])->get(env('SSO_HOST') . '/api/user');
    $request->session()->put($responses->json());

    return redirect('/');
  }
  public function logout(Request $request)
  {
    $request->session()->invalidate();
    $request->session()->regenerateToken();
    return redirect(env('SSO_HOST_LOGOUT'));
  }
}
