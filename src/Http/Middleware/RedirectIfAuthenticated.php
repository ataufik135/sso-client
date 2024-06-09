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
    $user = $request->session()->get('user');

    if (!$user || !$this->isUserAuthenticated($user['id'])) {
      return $next($request);
    }

    return redirect(RouteServiceProvider::HOME);
  }

  private function isUserAuthenticated($userId)
  {
    return $this->oauthClient->checkAuthUser($userId);
  }
}
