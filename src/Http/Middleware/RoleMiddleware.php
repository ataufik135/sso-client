<?php

namespace TaufikT\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use App\Providers\RouteServiceProvider;

class RoleMiddleware
{
  /**
   * Handle an incoming request.
   *
   * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
   */
  public function handle(Request $request, Closure $next, $role): Response
  {
    $user = $request->session()->get('user');
    if (!$user) {
      abort(403);
    }

    $roles = is_array($role) ? $role : explode('|', $role);

    if (count(array_intersect($roles, $user['roles'])) > 0) {
      return $next($request);
    }

    return redirect(RouteServiceProvider::HOME);
  }
}
