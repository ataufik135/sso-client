<?php

namespace TaufikT\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use TaufikT\SsoClient\OAuthClient;

class Authenticate
{
  protected $oauthClient;
  protected $logoutUri;
  protected $applicationId;

  public function __construct(OAuthClient $oauthClient)
  {
    $this->oauthClient = $oauthClient;
    $this->logoutUri = env('SSO_HOST_LOGOUT');
    $this->applicationId = env('SSO_CLIENT_ID');
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
        $this->oauthClient->reset();
        return redirect($this->logoutUri);
      }
      return $next($request);
    }

    return redirect(route('oauth2.redirect'));
  }

  private function buildApplicationIdIndex($user)
  {
    $index = [];
    foreach ($user['registrations'] as $registration) {
      $index[$registration['applicationId']] = true;
    }
    return $index;
  }

  private function isUserAuthorized($user)
  {
    $applicationIdIndex = $this->buildApplicationIdIndex($user);

    if (isset($applicationIdIndex[$this->applicationId])) {
      return $this->isUserValid();
    }

    return false;
  }

  protected function isUserValid()
  {
    return true;
  }
}
