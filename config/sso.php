<?php

return [
    'client_id' => env('SSO_CLIENT_ID'),
    'client_secret' => env('SSO_CLIENT_SECRET'),
    'client_callback' => env('SSO_CLIENT_CALLBACK'),
    'client_origin' => env('SSO_CLIENT_ORIGIN'),
    'scopes' => env('SSO_SCOPES'),
    'host' => env('SSO_HOST'),
    'host_logout' => env('SSO_HOST_LOGOUT'),
    'api_key' => env('SSO_API_KEY'),
    'jwt_public_key' => <<<EOD
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxGEziSD9mn55LMxA/WmI
B2jtqXOa/cFwoIdBr6plJU0R5+jYqcSFSIewQuoEF4jtV1T8FiSEibYI7cXstGg3
2z5d6WudlI85J63pC3KqnOYK7NrBzQxe3DH5EhgWlh12Ycz2pQjX6EFCWK9pU7Fi
rt3dhUCTdtEyNq+5raDjZIdhQq/UTYYmxWcfAqhjpWUARlct7G7flAU9aywwhLGX
rRqAU3b41EHnc6XfoL0QdrdtMlQAuyUdIg3Ru/sHl7MsZ1KyBwGS39sxmdjO/AkS
uXcoYv2AS1LCmlbu3F2M4N4LZwP6DFQKb4aO4Mr/Vp1gZssOCI0jM31EHhlm3RAR
9QIDAQAB
-----END PUBLIC KEY-----
EOD,
    'version' => '3.3.2'
];
