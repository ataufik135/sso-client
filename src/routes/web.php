<?php

use Illuminate\Support\Facades\Route;
use TaufikT\SsoClient\Http\Controllers\SSOController;

Route::controller(SSOController::class)->group(function () {
  Route::prefix('/oauth2')->group(function () {
    Route::get('/redirect', 'redirect')->name('oauth2.redirect')->middleware(['web', 'sso.guest']);
    Route::get('/callback', 'callback')->name('oauth2.callback')->middleware(['web', 'sso.guest']);
    Route::get('/logout', 'logout')->name('oauth2.logout')->middleware(['web', 'sso.auth']);
    Route::get('/endsession', 'backchannelLogout')->name('oauth2.endsession')->middleware('web');
  });
});
