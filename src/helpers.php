<?php

use Illuminate\Support\Facades\Session;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

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
function jwtDecrypt($payload)
{
  $publicKey = config('sso.jwt_public_key');
  return JWT::decode($payload, new Key($publicKey, 'RS256'));
}
