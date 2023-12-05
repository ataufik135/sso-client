<?php

use TaufikT\SsoClient\OAuthClient;

function checkSsoRole($role)
{
  $oauthClient = new OAuthClient();

  $user = session()->get('user');
  if (!$user) {
    if (!$getUser = $oauthClient->getUserInfo()) {
      session()->invalidate();
      session()->regenerateToken();
      return false;
    }
    $oauthClient->storeUser($getUser);
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
    return true;
  }
  return false;
}
