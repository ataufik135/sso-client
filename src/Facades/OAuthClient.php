<?php

namespace TaufikT\SsoClient\Facades;

use Illuminate\Support\Facades\Facade;

class OAuthClient extends Facade
{
  protected static function getFacadeAccessor()
  {
    return 'oauthclient';
  }
}
