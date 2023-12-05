<?php

namespace TaufikT\SsoClient\Http\Controllers;

use Illuminate\Http\Request;
use App\Providers\RouteServiceProvider;
use Illuminate\Support\Str;
use TaufikT\SsoClient\OAuthClient;

class SSOController
{
  protected $oauthClient;

  public function __construct(OAuthClient $oauthClient)
  {
    $this->oauthClient = $oauthClient;
  }

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
      'scope' => env('SSO_SCOPES'),
      'state' => $state,
    ]);

    return redirect(env('SSO_HOST') . '/oauth/authorize?' . $query);
  }
  public function callback(Request $request)
  {
    $state = $request->session()->pull('state');

    if (strlen($state) < 1 && $state !== $request->state) {
      return response()->json(['message' => 'Invalid state value.'], 400);
    }

    try {
      $requestToken = $this->oauthClient->requestToken($request->code);
      $this->oauthClient->storeToken($requestToken);
    } catch (\Exception $e) {
      return response()->json(['message' => 'Unauthorized'], 403);
    }

    try {
      $this->oauthClient->isTokenDuplicate() ? $this->oauthClient->reset() : '';
    } catch (\Exception $e) {
      //
    }

    try {
      $getUser = $this->oauthClient->getUserInfo();
      $this->oauthClient->storeUser($getUser);
    } catch (\Exception $e) {
      $this->oauthClient->reset();
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

    if ($this->oauthClient->logout($token)) {
      return response()->json(['message' => 'You have been successfully logged out'], 200);
    } else {
      return response()->json(['message' => 'Unauthorized'], 403);
    }
  }
}
