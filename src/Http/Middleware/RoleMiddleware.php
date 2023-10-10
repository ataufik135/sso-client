<?php

namespace TaufikT\SsoClient\Http\Middleware;

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
    if ($request->session()->has('access_token')) {
      $access_token = $request->session()->get('access_token');

      if (!$access_token) {
        return redirect()->route('oauth2.redirect');
      }

      $responses = Http::withHeaders([
        'Accept' => 'application/json',
        'Authorization' => 'Bearer ' . $access_token
      ])->get(env('SSO_HOST') . '/api/user');

      $user = $responses->json();

      if ($responses->status() == 200) {
        $responseTokens = Http::withHeaders([
          'Accept' => 'application/json',
        ])->get(env('SSO_HOST') . '/oauth/tokens');

        $groupedData = collect($responseTokens)->groupBy('client_id');
        $duplicates = $groupedData->filter(function ($items) {
          return $items->count() > 1;
        });

        if ($duplicates->isNotEmpty()) {
          return redirect()->route('oauth2.logout');
        }

        $request->session()->put($responses->json());
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

      return response()->json(['message' => 'Unauthorized'], 401);
    }

    return response()->json(['message' => 'Unauthorized'], 403);
  }
}
