<?php

namespace App\Http\Middleware\SSO;

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
    $access_token = $request->session()->get('access_token');
    $responses = Http::withHeaders([
      'Accept' => 'application/json',
      'Authorization' => 'Bearer ' . $access_token
    ])->get(env('SSO_HOST') . '/api/user');

    if ($responses->status() == 200) {
      return $next($request);
    }
    return redirect()->route('oauth.redirect');
    // return response()->json(['message' => 'Unauthorized middleware'], 401);
  }
}
