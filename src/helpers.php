<?php

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Session;

function checkSsoRole($role)
{
  $user = Session::get('user');
  if (!$user) {
    return false;
  }

  $roles = is_array($role) ? $role : explode('|', $role);

  $userRoles = [];
  $applicationId = Config::get('sso.client_id');
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
