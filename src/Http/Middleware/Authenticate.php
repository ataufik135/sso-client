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

      $user = $responses->json();

      if ($responses->status() == 200) {
        $responseTokens = Http::get(env('SSO_HOST') . '/oauth/tokens');

        if ($responseTokens->status() != 200) {
          return response()->json(['message' => 'Failed to retrieve tokens from SSO Server'], $responseTokens->status());
        }

        $groupedData = collect($responseTokens)->groupBy('client_id');
        $duplicates = $groupedData->filter(function ($items) {
          return $items->count() > 1;
        });

        if ($duplicates->isNotEmpty()) {
          return redirect()->route('oauth2.logout');
        }

        $request->session()->put($responses->json());
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
