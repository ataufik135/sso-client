<?php

namespace TaufikT\SsoClient;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ClientException;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Session;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class OAuthClient
{
  protected $config;
  protected $httpClient;
  protected $discovery;

  public function __construct()
  {
    $this->config = config('sso');
    $this->httpClient = new Client([
      'verify' => $this->config['ssl_verify'],
    ]);

    $this->discover();
  }

  protected function discover()
  {
    $response = $this->httpClient->get($this->config['discovery_url']);
    $this->discovery = json_decode($response->getBody(), true);
  }

  public function getAuthorizationUrl($state, $codeChallenge)
  {
    return $this->discovery['authorization_endpoint'] . '?' . http_build_query([
      'response_type' => 'code',
      'client_id' => $this->config['client_id'],
      'redirect_uri' => $this->config['client_callback'],
      'scope' => $this->config['scopes'],
      'state' => $state,
      'code_challenge' => $codeChallenge,
      'code_challenge_method' => 'S256',
    ]);
  }

  public function getToken($code, $codeVerifier, $requestIp)
  {
    try {
      $response = $this->httpClient->post($this->discovery['token_endpoint'], [
        'headers' => [
          'Accept' => 'application/json',
          'X-Forwarded-For' => $requestIp,
        ],
        'form_params' => [
          'grant_type' => 'authorization_code',
          'client_id' => $this->config['client_id'],
          'client_secret' => $this->config['client_secret'],
          'redirect_uri' => $this->config['client_callback'],
          'code_verifier' => $codeVerifier,
          'code' => $code,
        ],
      ]);

      $tokenResponse = json_decode($response->getBody(), true);

      if (isset($tokenResponse['error'])) {
        throw new \Exception("Error getting token: " . $tokenResponse['error_description']);
      }

      return $tokenResponse;
    } catch (ClientException $e) {
      $response = $e->getResponse();
      $statusCode = $response->getStatusCode();
      $errorBody = json_decode($response->getBody(), true);

      if (isset($errorBody['error'])) {
        $errorMessage = $errorBody['error_description'] ?? 'Unknown error';
        throw new \Exception("Token request failed: $errorMessage (HTTP $statusCode)");
      }

      throw new \Exception("Client error during token request: HTTP $statusCode");
    } catch (RequestException $e) {
      throw new \Exception("Network or server error: " . $e->getMessage());
    } catch (\Exception $e) {
      throw new \Exception("General error during token request: " . $e->getMessage());
    }
  }

  public function getUserInfo($accessToken)
  {
    try {
      $response = $this->httpClient->get($this->discovery['userinfo_endpoint'], [
        'headers' => [
          'Authorization' => 'Bearer ' . $accessToken,
          'Accept' => 'application/json',
        ],
      ]);

      return json_decode($response->getBody(), true);
    } catch (\Exception $e) {
      throw new \Exception("Failed to fetch userinfo: " . $e->getMessage());
    }
  }

  public function getLogoutUrl($redirectUrl = null)
  {
    return $this->config['host_logout'] . '?client_id=' . $this->config['client_id'] . ($redirectUrl !== null ? '&post_logout_redirect_uri=' . $redirectUrl : '');
  }

  public function destroyAllSessions()
  {
    $sessionDriver = config('session.driver');
    if ($sessionDriver !== 'file') {
      return false;
    }

    $sessionPath = config('session.files');
    $sessionFiles = File::files($sessionPath);
    $sessionHandler = Session::getHandler();

    foreach ($sessionFiles as $file) {
      $sessionId = $file->getFilename();
      $sessionHandler->destroy($sessionId);
    }
    return true;
  }
  public function destroySessionByUserId($userId)
  {
    $sessionDriver = config('session.driver');
    if ($sessionDriver !== 'file') {
      return false;
    }

    $sessionPath = config('session.files');
    $sessionFiles = File::files($sessionPath);
    $sessionHandler = Session::getHandler();

    foreach ($sessionFiles as $file) {
      $sessionData = $file->getContents();

      if (strpos($sessionData, $userId) !== false) {
        $sessionId = $file->getFilename();
        $sessionHandler->destroy($sessionId);
      }
    }
    return true;
  }

  public function verifyToken($token)
  {
    try {
      $jwksUri = $this->discovery['jwks_uri'];
      $jwksResponse = $this->httpClient->get($jwksUri);
      $jwksKeys = json_decode($jwksResponse->getBody(), true);
      $publicKey = $this->getPublicKeyFromJWKS($jwksKeys['keys'][0]);
      $decodedToken = JWT::decode($token, new Key($publicKey, 'RS256'));
      return $decodedToken;
    } catch (\Exception $e) {
      return false;
    }
  }

  protected function getPublicKeyFromJWKS($jwks)
  {
    $modulus = JWT::urlsafeB64Decode($jwks['n']);
    $exponent = JWT::urlsafeB64Decode($jwks['e']);

    $components = [
      'modulus' => pack('Ca*a*', 2, $this->encodeLength(strlen($modulus)), $modulus),
      'publicExponent' => pack('Ca*a*', 2, $this->encodeLength(strlen($exponent)), $exponent)
    ];

    $rsaPublicKey = pack(
      'Ca*a*a*',
      48,
      $this->encodeLength(strlen($components['modulus']) + strlen($components['publicExponent'])),
      $components['modulus'],
      $components['publicExponent']
    );

    $rsaPublicKeyPem = "-----BEGIN PUBLIC KEY-----\r\n" .
      chunk_split(base64_encode($rsaPublicKey), 64) .
      "-----END PUBLIC KEY-----";

    return $rsaPublicKeyPem;
  }
  protected function encodeLength($length)
  {
    if ($length <= 0x7F) {
      return chr($length);
    }

    $temp = ltrim(pack('N', $length), chr(0));
    return pack('Ca*', 0x80 | strlen($temp), $temp);
  }
}
