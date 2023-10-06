# SSO Client

Integrate Laravel Framework with Single Sign-On (SSO) Client using OAuth2.

##### install

    composer require taufik-t/sso-client

##### .env

    SSO_CLIENT_ID="9a490422-0cdb-48bb-8ea4-c816786089f4"
    SSO_CLIENT_SECRET="VNj0KAWJp2IfSlk2c7L67jdrPPhc0apMZVgDiSxs"
    SSO_CLIENT_CALLBACK="http://app.client.com/oauth2/callback"
    SSO_CLIENT_ORIGIN="http://app.client.com"
    SSO_SCOPES=""
    SSO_HOST="http://sso.server.com"
    SSO_HOST_LOGOUT="http://sso.server.com/logout"

##### config/app.php

    'providers' => ServiceProvider::defaultProviders()->merge([
        // ...
        TaufikT\SsoClient\SSOServiceProvider::class,
    ])->toArray(),

##### app/Http/Kernel.php

    protected $middlewareAliases = [
        // ...
        'sso.auth' => \TaufikT\SsoClient\Http\Middleware\Authenticate::class,
        'sso.guest' => \TaufikT\SsoClient\Http\Middleware\RedirectIfAuthenticated::class,
        'sso.role' => \TaufikT\SsoClient\Http\Middleware\RoleMiddleware::class,
    ];

### Middleware via Routes

    Route::group(['middleware' => ['sso.auth']], function () {
        // authenticated users only
    });
    Route::group(['middleware' => ['sso.guest']], function () {
        // unauthenticated users only
    });
    Route::group(['middleware' => ['sso.role:user']], function () {
        // users with specified role only
    });
    Route::group(['middleware' => ['sso.role:user|admin|manager']], function () {
        // users with specified roles only
    });

### Middleware with Controllers

    public function __construct()
    {
        $this->middleware(['sso.role:super-admin']);
    }
