<?php

namespace App\Http\Controllers\api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\User;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function register(Request $request) {
    	$request->validate([
    		'name' => 'required | string',
    		'email' => 'required | email | string | unique:users',
    		'password' => 'required | string | confirmed',
    	]);
    	
    	$user = new User([
    		'name' => $request->name,
    		'email' => $request->email,
    		'password' => bcrypt($request->password)
    	]);

    	$user->save();

    	return response()->json([
    		'message' => 'User Registration Successful'
    	], 201);
    }

    public function login(Request $request) {
    	$request->validate([
    		'email' => 'required | string | email',
    		'password' => 'required | string'
    	]);

    	$credentials = request(['email', 'password']);

    	if(!Auth::attempt($credentials)) {
    		return response()->json([
    			'message' => 'Invalid Credentials'
    		], 401);
    	}

    	$user = $request->user();

    	$token = $user->createToken('token');

    	$user->token = $token->accessToken;

    	return response()->json([
    		'user' => $user
    	], 200);
    }

    public function logout(Request $request) {
    	$request->user()->token()->revoke();
    	return response()->json([
    		'message' => 'User logged out successfully'
    	], 200);
    }

    public function check() {
    	return "Check Success";
    }
}
