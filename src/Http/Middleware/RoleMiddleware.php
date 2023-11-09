<?php

namespace TaufikT\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RoleMiddleware
{
  /**
   * Handle an incoming request.
   *
   * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
   */
  public function handle(Request $request, Closure $next, $role): Response
  {
    $user = session()->get('user');
    $hasExpired = hasExpired();
    if (!$user || $hasExpired) {
      if (!getUser()) {
        return response()->json(['message' => 'Unauthorized'], 401);
      }
      $user = session()->get('user');
    }

    $roles = is_array($role) ? $role : explode('|', $role);

    $userRoles = [];
    $applicationId = env('SSO_CLIENT_ID');
    foreach ($user['registrations'] as $registration) {
      if ($registration['applicationId'] === $applicationId) {
        $userRoles = $registration['roles'];
        break;
      }
    }

    if (count(array_intersect($roles, $userRoles)) > 0) {
      return $next($request);
    }
    return response()->json(['message' => 'Unauthorized'], 403);
  }
}
