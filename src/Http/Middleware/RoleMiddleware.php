<?php

namespace TaufikT\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use TaufikT\SsoClient\OAuthClient;
use App\Providers\RouteServiceProvider;

class RoleMiddleware
{
  protected $oauthClient;

  public function __construct(OAuthClient $oauthClient)
  {
    $this->oauthClient = $oauthClient;
  }

  /**
   * Handle an incoming request.
   *
   * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
   */
  public function handle(Request $request, Closure $next, $role): Response
  {
    $user = $request->session()->get('user');
    if (!$user) {
      return response()->json(['message' => 'Unauthorized'], 401);
    }

    $roles = is_array($role) ? $role : explode('|', $role);

    $userRoles = [];
    foreach ($user['registrations'] as $registration) {
      if ($registration['applicationId'] === $this->oauthClient->clientId()) {
        $userRoles = $registration['roles'];
        break;
      }
    }

    if (count(array_intersect($roles, $userRoles)) > 0) {
      return $next($request);
    }

    return redirect(RouteServiceProvider::HOME);
  }
}
