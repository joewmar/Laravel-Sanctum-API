<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Hash;


class AuthController extends Controller
{
    // Logout & Delete Token
    public function register(Request $request){
        $fields = $request->validate([
            'name' => ['required', 'min:3'],
            'email' => ['required', 'email', Rule::unique('users', 'email')],
            'password' => 'required|confirmed|min:6'
        ]);

        // Hash password
        $fields['password'] = bcrypt($fields['password']);

        // Create User
        $user = User::create($fields);

        // this token was use to able access protected routes
        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];
        return response($response, 201);
    }

    // Logout Authorization
    public function logout(Request $request){
        // Delete Token
         auth()->user()->tokens()->delete(); 

         return [
            'message' => 'Logged out'
         ];
    }

    // Login & Get Token
    public function login(Request $request){
        $fields = $request->validate([
            'email' => ['required', 'email'],
            'password' => 'required|min:6'
        ]);

        // Check Email
        $user = User::where('email', $fields['email'])->first();

        // Check Password
        if(!$user || !Hash::check($fields['password'], $user->password)){
            return response([
                'message' => 'Bad Credentials'
            ], 401);
        }

        // this token was use to able access protected routes
        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];
        return response($response, 201);
    }
}
