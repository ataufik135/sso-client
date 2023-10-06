<?php

namespace App\Http\Middleware\SSO;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Http;

class RoleMiddleware
{
  /**
   * Handle an incoming request.
   *
   * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
   */
  public function handle(Request $request, Closure $next, $role): Response
  {
    $access_token = $request->session()->get('access_token');

    if (!$access_token) {
      return response()->json(['message' => 'Unauthorized'], 403);
    }

    $responses = Http::withHeaders([
      'Accept' => 'application/json',
      'Authorization' => 'Bearer ' . $access_token
    ])->get(env('SSO_HOST') . '/api/user');

    if ($responses->status() != 200) {
      return response()->json(['message' => 'Unauthorized'], 401);
    }
    $user = $responses->json();

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
