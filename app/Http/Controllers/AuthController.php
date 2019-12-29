<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Http\Request;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\BadResponseException;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $http = new Client;

        try {
            $response = $http->post(
                route('passport.token'),
                [
                    'form_params' => [
                        'grant_type' => 'password',
                        'client_id' => config('services.passport.client_id'),
                        'client_secret' => config('services.passport.client_secret'),
                        'username' => $request->email,
                        'password' => $request->password
                    ],
                ]
            );

            return $response->getBody();
        } catch (BadResponseException $e) {
            if ($e->getCode() === 400) {
                return response()->json('Invalid Request. Please enter a username or a password. ' . $request->password, $e->getCode());
            } elseif ($e->getCode() === 401) {
                return response()->json('Your credentials are incorrect. Please try again.', $e->getCode());
            }

            return response()->json('Something went wrong on the server.', $e->getCode());
        }
    }

    public function register(Request $request)
    {
        $request->validate(
            [
                'name' => ['required', 'string', 'max:255'],
                'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
                'password' => ['required', 'string', 'min:8'],
            ]
        );

        return User::create(
            [
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]
        );
    }

    public function logout()
    {
        auth()->user()->tokens->each(
            function ($token, $key) {
                $token->delete();
            }
        );

        return response()->json('Logged out successfully', 200);
    }
}
