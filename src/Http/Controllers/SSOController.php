<?php

namespace TaufikT\SsoClient\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;
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
    $requestUrl = $request->session()->pull('request_url');
    $requestIp = $request->session()->pull('request_ip');
    $state = $request->session()->pull('state');
    $codeVerifier = $request->session()->pull('code_verifier');

    if (strlen($state) < 1 && $state !== $request->state) {
      return response()->json(['message' => 'Invalid state value.'], 400);
    }

    try {
      $response = $this->oauthClient->requestToken($request->code, $codeVerifier, $requestIp);

      $statusCode = $response->getStatusCode();
      $responseData = json_decode($response->getBody(), true);
      if ($statusCode === 400) {
        return response()->json($responseData, $statusCode);
      }
      if ($statusCode === 200) {
        $user = $request->session()->get('user');

        $request->session()->regenerate();
        $clientSessionId = Session::getId();
        $this->oauthClient->addAuthUser($user['id'], $user['sessionId'], $clientSessionId);
        return $requestUrl !== null ? redirect($requestUrl) : redirect()->intended('/');
      }

      $userId = $request->session()->get('userId');
      $clientSessionId = Session::getId();
      $this->oauthClient->addUnauthUser($userId, $clientSessionId);
      throw new \Exception('Unauthorized.');
    } catch (\Exception $e) {
      abort(403);
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
    $token = $request->bearerToken();
    if (!$token) {
      $request->session()->invalidate();
      $request->session()->regenerateToken();
      return response()->json(['status' => true], 200);
    }

    $this->oauthClient->logout($token);
    return response()->json(['message' => 'You have been logged out!'], 200);
  }
}
