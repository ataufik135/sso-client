<?php

return [
  // OpenID Connect Discovery URL
  'discovery_url' => env('OIDC_DISCOVERY_URL', env('SSO_HOST') . '/.well-known/openid-configuration'),

  // Client Credentials
  'client_id' => env('SSO_CLIENT_ID'),
  'client_secret' => env('SSO_CLIENT_SECRET'),
  'client_callback' => env('SSO_CLIENT_CALLBACK'),
  'client_origin' => env('SSO_CLIENT_ORIGIN'),

  // Scopes (default: 'openid profile email')
  'scopes' => env('SSO_SCOPES', 'openid profile email'),

  // Host Information
  'host' => env('SSO_HOST'),
  'host_logout' => env('SSO_HOST_LOGOUT'),

  // SSL Verification
  'ssl_verify' => env('SSO_SSL_VERIFY', true),

  // API Key for additional requests
  'api_key' => env('SSO_API_KEY'),
];
