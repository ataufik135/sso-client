<?php

namespace TaufikT\SsoClient;

include_once(__DIR__ . '/Helpers/SSO.php');

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Blade;

class SSOServiceProvider extends ServiceProvider
{
  /**
   * Register services.
   */
  public function register(): void
  {
    $this->app->bind('oauthclient', function ($app) {
      return new OAuthClient();
    });
  }

  /**
   * Bootstrap services.
   */
  public function boot(): void
  {
    $this->loadRoutesFrom(__DIR__ . '/routes/web.php');

    Blade::directive('ssoRole', function ($role) {
      return '<?php if(checkSsoRole(' . $role . ')): ?>';
    });

    Blade::directive('endSsoRole', function () {
      return '<?php endif; ?>';
    });
  }
}
