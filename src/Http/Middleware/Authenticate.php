<?php

namespace TaufikT\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class Authenticate
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
      return redirect(route('oauth2.redirect'));
    }

    $isUserAuthorized = $this->isUserAuthorized($user);

    if (($access_token && !$hasExpired) && $isUserAuthorized) {
      return $next($request);
    }

    if (($access_token && !$hasExpired) && !$isUserAuthorized) {
      return response()->json(['message' => 'Unauthorized'], 401);
    }

    if (($access_token && refreshToken()) && $isUserAuthorized) {
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
