<?php

namespace TaufikT\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Http;

class Authenticate
{
  /**
   * Handle an incoming request.
   *
   * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
   */
  public function handle(Request $request, Closure $next): Response
  {
    if ($request->session()->has('access_token')) {
      $access_token = $request->session()->get('access_token');
      $responses = Http::withHeaders([
        'Accept' => 'application/json',
        'Authorization' => 'Bearer ' . $access_token
      ])->get(env('SSO_HOST') . '/api/user');

      $request->session()->put($responses->json());
      $user = $responses->json();

      if ($responses->status() == 200) {
        $applicationId = env('SSO_CLIENT_ID');
        foreach ($user['registrations'] as $registration) {
          if ($registration['applicationId'] === $applicationId) {
            return $next($request);
            break;
          }
        }
        return response()->json(['message' => 'Unauthorized'], 403);
      }
      return redirect()->route('oauth2.redirect');
    }
    return redirect()->route('oauth2.redirect');
  }
}
