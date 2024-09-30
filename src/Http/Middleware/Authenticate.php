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
    $user = $request->session()->get('user');

    if (!$user) {
      return redirect()->route('oauth2.redirect');
    }

    if (!$this->isUserAuthorized()) {
      abort(403);
    }

    return $next($request);
  }

  private function isUserAuthorized()
  {
    return $this->isUserValid();
  }
  protected function isUserValid()
  {
    return true;
  }
}
