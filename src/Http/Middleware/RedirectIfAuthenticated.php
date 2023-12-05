<?php

namespace TaufikT\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use App\Providers\RouteServiceProvider;
use TaufikT\SsoClient\OAuthClient;

class RedirectIfAuthenticated
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

    if (!$access_token || !$user) {
      return $next($request);
    }

    $isTokenExpired = $this->oauthClient->isTokenExpired();
    if (!$isTokenExpired) {
      return redirect(RouteServiceProvider::HOME);
    }

    if ($refreshToken = $this->oauthClient->refreshToken()) {
      $this->oauthClient->storeToken($refreshToken);
      if ($this->oauthClient->isTokenDuplicate()) {
        $this->oauthClient->reset();
      }
      return redirect(RouteServiceProvider::HOME);
    }

    return $next($request);
  }
}
