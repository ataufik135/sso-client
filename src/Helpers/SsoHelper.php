<?php

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Session;

function checkSsoRole($role)
{
  $user = session()->get('user');
  if (!$user) {
    if (getUser() !== true) {
      session()->invalidate();
      session()->regenerateToken();
      return false;
    }
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

function hasExpired()
{
  $authAt = session()->get('auth_at');
  $expiresIn = session()->get('expires_in');

  if ($authAt === null || $expiresIn === null) {
    return true;
  }

  $authAtCarbon = \Carbon\Carbon::parse($authAt);
  $now = \Carbon\Carbon::now();

  return $now->gte($authAtCarbon->addSeconds($expiresIn));
}

function refreshToken()
{
  $refresh_token = session()->get('refresh_token');
  $response = Http::asForm()->post(
    env('SSO_HOST') . '/oauth/token',
    [
      'grant_type' => 'refresh_token',
      'refresh_token' => $refresh_token,
      'client_id' => env('SSO_CLIENT_ID'),
      'client_secret' => env('SSO_CLIENT_SECRET'),
      'redirect_uri' => env('SSO_CLIENT_CALLBACK'),
      'scope' => env('SSO_SCOPES'),
    ]
  );

  if ($response->status() !== 200) {
    return false;
  }

  $now = \Carbon\Carbon::now()->toIso8601String();
  session(['auth_at' => $now]);
  session()->put($response->json());

  $access_token = session()->get('access_token');
  $responseTokens = Http::withHeaders([
    'Accept' => 'application/json',
    'Authorization' => 'Bearer ' . $access_token
  ])->get(env('SSO_HOST') . '/api/tokens');

  if ($responseTokens->status() !== 200) {
    return false;
  }

  $tokens = $responseTokens->json();
  $groupedData = collect($tokens)->groupBy('client_id');
  $duplicates = $groupedData->filter(function ($items) {
    return $items->count() > 1;
  });

  if ($duplicates->isNotEmpty()) {
    return false;
  }

  if (!getUser()) {
    return redirect(route('oauth2.logout'));
  }

  return true;
}

function getUser()
{
  $access_token = session()->get('access_token');
  $hasExpired = hasExpired();
  if ($hasExpired) {
    if (!refreshToken()) {
      return redirect(route('oauth2.logout'));
    }
  }

  $response = Http::withHeaders([
    'Accept' => 'application/json',
    'Authorization' => 'Bearer ' . $access_token
  ])->get(env('SSO_HOST') . '/api/user');

  if ($response->status() !== 200) {
    return false;
  }

  $user = session()->get('user');
  if ($user['sessionId'] !== $response['sessionId']) {
    return redirect(route('oauth2.logout'));
  }

  session()->forget('user');
  session()->put('user', $response->json());

  return true;
}

function destroySessionById($id)
{
  $sessionPath = storage_path('framework/sessions');
  $sessionFiles = scandir($sessionPath);

  foreach ($sessionFiles as $file) {
    if ($file !== '.' && $file !== '..') {
      $sessionData = file_get_contents($sessionPath . DIRECTORY_SEPARATOR . $file);

      if (strpos($sessionData, $id) !== false) {
        $sessionId = pathinfo($file, PATHINFO_FILENAME);
        Session::getHandler()->destroy($sessionId);
      }
    }
  }

  return true;
}
