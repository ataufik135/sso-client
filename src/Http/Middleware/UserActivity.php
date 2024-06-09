<?php

namespace TaufikT\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\HttpFoundation\Response;
use TaufikT\SsoClient\OAuthClient;

class UserActivity
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
  public function handle(Request $request, Closure $next): Response
  {
    $user = $request->session()->get('user');
    if ($user && $this->isUserAuthenticated($user['id'])) {
      $expiresAt = now()->addMinutes(2);
      Cache::put('user-is-online-' . $user['id'], true, $expiresAt);

      if (!Cache::has('online-users')) {
        $userIds = $this->oauthClient->getAllUserIdAuthUser();
        $onlineUsers = [];
        foreach ($userIds as $userId) {
          if (Cache::has('user-is-online-' . $userId)) {
            $onlineUsers[] = $userId;
          }
        }

        $this->oauthClient->updateOnlineUsers($onlineUsers);
        Cache::put('online-users', true, $expiresAt);
      }
    }
    return $next($request);
  }

  private function isUserAuthenticated($userId)
  {
    return $this->oauthClient->checkAuthUser($userId);
  }
}
