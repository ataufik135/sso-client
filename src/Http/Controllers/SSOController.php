<?php

namespace TaufikT\SsoClient\Http\Controllers;

use Illuminate\Http\Request;
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
    $request->session()->put('request_url', $request->session()->get('_previous.url'));
    $request->session()->put('request_ip', $request->ip());
    $request->session()->put('state', $state = Str::random(40));
    $request->session()->put('code_verifier', $code_verifier = Str::random(128));
    $codeChallenge = strtr(rtrim(base64_encode(hash('sha256', $code_verifier, true)), '='), '+/', '-_');

    return redirect($this->oauthClient->getAuthorizationUrl($state, $codeChallenge));
  }

  public function callback(Request $request)
  {
    $requestUrl = $request->session()->pull('request_url');
    $requestIp = $request->session()->pull('request_ip');
    $state = $request->session()->pull('state');
    $codeVerifier = $request->session()->pull('code_verifier');
    $code = $request->code;

    if (strlen($state) < 1 && $state !== $request->state) {
      return response()->json(['message' => 'Invalid state value.'], 400);
    }

    try {
      $token = $this->oauthClient->getToken($code, $codeVerifier, $requestIp);
      $userInfo = $this->oauthClient->getUserInfo($token['access_token']);
      if (!isset($userInfo['id'])) {
        $userInfo['id'] = $userInfo['sub'] ?? null;
      }

      $request->session()->put($token);
      $request->session()->put('user', $userInfo);
      $request->session()->regenerate();
      return $requestUrl !== null ? redirect($requestUrl) : redirect()->intended('/');
    } catch (\Exception $e) {
      return response()->json([
        'error' => 'Token or userinfo request failed',
        'message' => $e->getMessage(),
      ], 500);
    }
  }

  public function logout(Request $request)
  {
    $redirectUrl = $request->query('redirect', null);
    $request->session()->invalidate();
    $request->session()->regenerateToken();
    return redirect()->away($this->oauthClient->getLogoutUrl($redirectUrl));
  }

  public function backchannelLogout(Request $request)
  {
    $token = $request->bearerToken();
    if (!$token) {
      $request->session()->invalidate();
      $request->session()->regenerateToken();
      return response()->json([], 200);
    }

    $token = $this->oauthClient->verifyToken($token);
    if ($token['aud'] === config('sso.client_id')) {
      if ($token['sub']) {
        $response = $this->oauthClient->destroySessionByUserId($token['sub']);
        if (!$response) {
          return response()->json([
            'error' => 'Logout request unsuccessful',
            'message' => 'The user logout attempt has failed.'
          ], 500);
        }
      }

      if ($token['event'] === "destroy all sessions") {
        $response = $this->oauthClient->destroyAllSessions();
        if ($response) {
          return response()->json([
            'success' => 'Destroy all sessions successful',
            'message' => 'All session has been destroyed successfully.'
          ], 200);
        }
      }
    }

    return response()->json([
      'success' => 'Logout successful',
      'message' => 'The user has been logged out successfully.!'
    ], 200);
  }
}
