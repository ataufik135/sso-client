<?php

function checkSsoRole($role)
{
  $user = session()->get('user');
  if (!$user) {
    return false;
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
