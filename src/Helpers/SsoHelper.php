<?php

use Illuminate\Support\Facades\Http;

function checkSsoRole($role)
{
  if (session()->has('access_token')) {
    $access_token = session()->get('access_token');

    if ($access_token) {
      $responses = Http::withHeaders([
        'Accept' => 'application/json',
        'Authorization' => 'Bearer ' . $access_token
      ])->get(env('SSO_HOST') . '/api/user');

      if ($responses->status() == 200) {
        $user = $responses->json();

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
      }
    }
    return false;
  }
  return false;
}
