<?php

use App\Http\Controllers\ProductController;
use App\Http\Controllers\AuthController;
use App\Models\Product;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// http://laravel-sanctum-api.test/api/products


// Public Routes
// Route::resource('products', ProductController::class);


// Register User Route with Token
Route::post('/register', [AuthController::class, 'register']);

// Login User Route with Token
Route::post('/login', [AuthController::class, 'login']);

Route::get('/products', [ProductController::class, 'index']);
Route::get('/products/{id}', [ProductController::class, 'show']);
// Route::get('/products/{id}', [ProductController::class, 'show']);

// Seach Through Product Name
Route::get('/products/search/{name}', [ProductController::class, 'search']);



// Protected Routes
Route::group(['middleware' => ['auth:sanctum']], function() {
    // Route::get('/products/search/{name}', [ProductController::class, 'search']);
    Route::post('/products', [ProductController::class, 'store']);
    Route::put('/products/{id}', [ProductController::class, 'update']);
    Route::delete('/products/{id}', [ProductController::class, 'destroy']);
    
    // Logout Auth Route
    Route::post('/logout', [AuthController::class, 'logout']);
});

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});
