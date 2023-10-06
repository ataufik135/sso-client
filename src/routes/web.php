<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Http\Request;
use App\Http\Controllers\SSO\SSOController;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

Route::controller(SSOController::class)->group(function () {
  Route::prefix('/oauth2')->group(function () {
    Route::get('/redirect', 'redirect')->name('oauth2.redirect')->middleware('sso.guest');
    Route::get('/callback', 'callback')->name('oauth2.callback')->middleware('sso.guest');
    Route::get('/logout', 'logout')->name('oauth2.logout')->middleware('sso.auth');
  });
});

// Route::get('/userinfo', 'userInfo')->name('userinfo')->middleware(['sso.auth', 'sso.role:user']);
// Route::get('/authuser', [SSOController::class, 'connectUser']);

// Route::get('/', function () {
//   return view('welcome');
// })->middleware('sso.auth');
