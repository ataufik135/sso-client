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
    $access_token = session()->get('access_token');
    $user = session()->get('user');
    $isTokenExpired = $this->oauthClient->isTokenExpired();

    if (!$access_token || !$user) {
      return redirect(route('oauth2.redirect'));
    }

    $isUserAuthorized = $this->isUserAuthorized($user);

    if (!$isUserAuthorized) {
      return response()->json(['message' => 'Unauthorized'], 401);
    }

    if (!$isTokenExpired) {
      return $next($request);
    }

    if ($refreshToken = $this->oauthClient->refreshToken()) {
      $this->oauthClient->storeToken($refreshToken);
      if ($this->oauthClient->isTokenDuplicate()) {
        $this->oauthClient->reset();
      }
      return $next($request);
    }

    return redirect(route('oauth2.redirect'));
  }

  private function isUserAuthorized($user)
  {
    $applicationId = env('SSO_CLIENT_ID');

    foreach ($user['registrations'] as $registration) {
      if ($registration['applicationId'] === $applicationId) {
        if ($this->isUserValid()) {
          return true;
        }
        return false;
      }
    }

    return false;
  }

  protected function isUserValid()
  {
    return true;
  }
}
