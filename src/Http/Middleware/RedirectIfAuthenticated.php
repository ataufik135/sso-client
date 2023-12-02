<?php

namespace TaufikT\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use App\Providers\RouteServiceProvider;

class RedirectIfAuthenticated
{
  /**
   * Handle an incoming request.
   *
   * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
   */
  public function handle(Request $request, Closure $next): Response
  {
    $access_token = session()->get('access_token');
    $user = session()->get('user');
    $hasExpired = hasExpired();

    if (!$user) {
      return $next($request);
    }

    if ($access_token && !$hasExpired) {
      return redirect(RouteServiceProvider::HOME);
    }

    if ($access_token && $hasExpired) {
      if (refreshToken()) {
        return redirect(RouteServiceProvider::HOME);
      }

      session()->invalidate();
      session()->regenerateToken();
      return redirect(route('oauth2.redirect'));
    }

    return $next($request);
  }
}
