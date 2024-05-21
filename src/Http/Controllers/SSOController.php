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
    $request->session()->put('state', $state = Str::random(40));
    $request->session()->put('code_verifier', $code_verifier = Str::random(128));
    $codeChallenge = strtr(rtrim(base64_encode(hash('sha256', $code_verifier, true)), '='), '+/', '-_');

    $query = http_build_query([
      'response_type' => 'code',
      'client_id' => $this->oauthClient->clientId(),
      'redirect_uri' => $this->oauthClient->redirectUri(),
      'scope' => $this->oauthClient->scopes(),
      'state' => $state,
      'code_challenge' => $codeChallenge,
      'code_challenge_method' => 'S256',
    ]);

    return redirect($this->oauthClient->host() . '/oauth/authorize?' . $query);
  }
  public function callback(Request $request)
  {
    $state = $request->session()->pull('state');
    $codeVerifier = $request->session()->pull('code_verifier');

    if (strlen($state) < 1 && $state !== $request->state) {
      return response()->json(['message' => 'Invalid state value.'], 400);
    }

    try {
      $requestToken = $this->oauthClient->requestToken($request->code, $codeVerifier);
      $this->oauthClient->storeToken($requestToken);

      $isTokenDuplicate = $this->oauthClient->isTokenDuplicate();
      if ($isTokenDuplicate === true) {
        return $this->logout($request);
      }

      $getUser = $this->oauthClient->getUserInfo();
      $this->oauthClient->storeUser($getUser);

      $request->session()->regenerate();
      return redirect(RouteServiceProvider::HOME);
    } catch (\Exception $e) {
      return response()->json(['message' => 'Unauthorized'], 403);
    }
  }

  public function logout(Request $request)
  {
    $request->session()->invalidate();
    $request->session()->regenerateToken();
    return redirect($this->oauthClient->logoutUri());
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
