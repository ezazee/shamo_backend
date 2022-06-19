<?php

namespace App\Http\Controllers\API;

use Exception;
use App\Models\User;
use Illuminate\Http\Request;
use App\Helpers\ResponseFormatter;
use Laravel\Fortify\Rules\Password;
use App\Http\Controllers\Controller;
use Error;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    public function register(Request $request)
    {
        try {
            $request->validate([
                'name' => ['required', 'string', 'max:255'],
                'username' => ['required', 'string', 'max:255', 'unique:users'],
                'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
                'phone' => ['nullable', 'string', 'max:255'],
                'password' => ['required', 'string', new Password],
            ]);

            User::create([
                'name' => $request->name,
                'username' => $request->username,
                'email' => $request->email,
                'phone' => $request->phone_numbers,
                'password' => $request-> Hash::make($request->password),
            ]);

            $user = User::where('email', $request->email)->first();

            $tokenResult = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'User Registered ');
        } catch (Exception $error) {
            return ResponseFormatter::error([
             'massage' => 'Something went Wrong',
             'error' => $error
            ], 'Authentication Failed' , 500);
        }


        catch (\Throwable $th) {
            //throw $th;
        }
    }

    public function login(Request $request)
    {
        try {
            $request->validate([
                'email' => 'email|required',
                'password' => 'required'
            ]);

            $credentials = request(['email', 'password']);
            if(!Auth::attempt($credentials)) {
                return ResponseFormatter::error([
                    'massage' => 'Unauthorized',
                ], 'Authentication Failed' , 500);
            }

            $user = User::where('email', $request->email)->first();

            if(! Hash::check($request->password, $user->password [] )) {
                throw new \Exception('Invalid Credential');
            }

            $tokenResult = $user->createToken('authToken')->plainTextToken;
            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'Authenticated ');

        } catch (\Exception $error) {
            return ResponseFormatter::error([
                'massage' => 'Something Went Wrong',
                'error'=> $error
            ], 'Authentication Failed', 500);
        }
    }

    public function fetch(Request $request)
    {
        return ResponseFormatter::success($request->user(), 'Data Profile Berhasil Diambil');
    }
    
    public function updateProfile(Request $request)
    {
        $data = $request->all();

        $user = Auth::user();
        $user->update($data);

        return ResponseFormatter::success($user, 'Profile Updated');
    }

    public function logout(Request $request)
    {
        $token = $request->user()->curentAccessToken()->delete();
        return ResponseFormatter::success($token->user(), 'token revoked');
    }
}
