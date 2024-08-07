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
    $user = $request->session()->get('user');
    $status = $request->session()->get('status');

    if ($status === 403) {
      abort(403);
    }

    if (!$user || !$this->isUserAuthenticated($user['id'])) {
      return redirect()->route('oauth2.redirect');
    }

    if (!$this->isUserAuthorized($user['applicationId'])) {
      abort(403);
    }

    return $next($request);
  }

  private function isUserAuthorized($applicationId)
  {
    if ($applicationId === $this->oauthClient->clientId()) {
      return $this->isUserValid();
    }

    return false;
  }
  private function isUserAuthenticated($userId)
  {
    return $this->oauthClient->checkAuthUser($userId);
  }

  protected function isUserValid()
  {
    return true;
  }
}
