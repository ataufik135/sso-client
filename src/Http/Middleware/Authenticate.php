<?php

namespace TaufikT\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use TaufikT\SsoClient\OAuthClient;

class Authenticate
{
  protected $oauthClient;

  public function __construct(OAuthClient $oauthClient)
  {
    $this->oauthClient = $oauthClient;
  }

  /**
   * Handle an incoming request.
   *
   * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
   */
  public function handle(Request $request, Closure $next): Response
  {
    $access_token = $request->session()->get('access_token');
    $user = $request->session()->get('user');

    if (!$access_token || !$user) {
      return redirect(route('oauth2.redirect'));
    }

    $isUserAuthorized = $this->isUserAuthorized($user);
    if (!$isUserAuthorized) {
      return response()->json(['message' => 'Unauthorized'], 401);
    }

    $isTokenExpired = $this->oauthClient->isTokenExpired();
    if (!$isTokenExpired) {
      return $next($request);
    }

    if ($refreshToken = $this->oauthClient->refreshToken()) {
      $this->oauthClient->storeToken($refreshToken);
      if ($this->oauthClient->isTokenDuplicate()) {
        return redirect($this->oauthClient->logoutUri());
      }
      return $next($request);
    }

    return redirect(route('oauth2.redirect'));
  }

  private function isUserAuthorized($user)
  {
    foreach ($user['registrations'] as $registration) {
      if ($registration['applicationId'] === $this->oauthClient->clientId()) {
        return $this->isUserValid();
      }
    }

    return false;
  }

  protected function isUserValid()
  {
    return true;
  }
}
