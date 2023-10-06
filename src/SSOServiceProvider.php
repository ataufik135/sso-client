<?php

namespace TaufikT\SsoClient;

use Illuminate\Support\ServiceProvider;

class SSOServiceProvider extends ServiceProvider
{
  /**
   * Register services.
   */
  public function register(): void
  {
    //
  }

  /**
   * Bootstrap services.
   */
  public function boot(): void
  {
    $this->loadRoutesFrom(__DIR__ . 'routes/web.php');
  }
}
