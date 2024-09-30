<?php

use Illuminate\Support\Facades\Session;

function checkSsoRole($role)
{
  $user = Session::get('user');
  if (!$user) {
    return false;
  }

  $roles = is_array($role) ? $role : explode('|', $role);

  if (count(array_intersect($roles, $user['roles'])) > 0) {
    return true;
  }
  return false;
}
