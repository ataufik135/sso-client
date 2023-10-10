<?php

namespace TaufikT\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use App\Providers\RouteServiceProvider;
use Illuminate\Support\Facades\Http;

class RedirectIfAuthenticated
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

        return redirect(RouteServiceProvider::HOME);
      }

      return $next($request);
    }

    return $next($request);
  }
}
