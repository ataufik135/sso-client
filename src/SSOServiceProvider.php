<?php

namespace TaufikT\SsoClient;

include_once(__DIR__ . '/helpers.php');

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Blade;

class SSOServiceProvider extends ServiceProvider
{
  protected $configFileName = 'sso.php';
  /**
   * Register services.
   */
  public function register(): void
  {
    $this->app->bind('oauthclient', function ($app) {
      return new OAuthClient(config('sso'));
    });
  }

  /**
   * Bootstrap services.
   */
  public function boot(): void
  {
    $this->publishes([
      __DIR__ . '/../config/' . $this->configFileName => $this->getConfigPath(),
    ]);
    $this->loadRoutes();

    Blade::directive('ssoRole', function ($role) {
      return '<?php if(checkSsoRole(' . $role . ')): ?>';
    });

    Blade::directive('endSsoRole', function () {
      return '<?php endif; ?>';
    });
  }


  protected function getConfigPath()
  {
    return config_path($this->configFileName);
  }
  protected function loadRoutes()
  {
    $this->loadRoutesFrom(__DIR__ . '/routes/web.php');
  }
}
