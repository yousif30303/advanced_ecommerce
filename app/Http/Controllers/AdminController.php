<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Laravel\Fortify\Fortify;
use Laravel\Fortify\Features;
use Illuminate\Routing\Pipeline;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Hash;
use App\Http\Responses\LoginResponse;
use Illuminate\Contracts\Auth\StatefulGuard;
use Laravel\Fortify\Contracts\LogoutResponse;
use App\Actions\Fortify\AttemptToAuthenticate;
use Laravel\Fortify\Http\Requests\LoginRequest;
use Laravel\Fortify\Contracts\LoginViewResponse;
use Laravel\Fortify\Actions\EnsureLoginIsNotThrottled;
use Laravel\Fortify\Actions\PrepareAuthenticatedSession;
use App\Actions\Fortify\RedirectIfTwoFactorAuthenticatable;

class AdminController extends Controller
{
   
    public function loginForm(){
    	return view('auth.admin_login', ['guard' => 'admin']);
    }

    
    public function login(Request $request)
    {
        $validated = $request->validate([
            'email' => 'required|max:255',
            'password' => 'required',
        ]);

        if(!auth()->attempt($request->only('email','password'))){
            return back()->with('status','Invalid Login Details');
        }
        $notification = array(
            'message' => 'User Logged in Successfully', 
            'alert-type' => 'success'
        );
        

        return redirect()->route('admin.dashboard');
    }

    public function registerForm(){
    	return view('auth.admin_register', ['guard' => 'admin']);
    }


    public function register(Request $request){
        
        $validated = $request->validate([
            'name' => 'required|max:255',
            'username' => 'required|max:255',
            'email' => 'required|email|max:255',
            'password' => 'required',
        ]);
    

        User::create([
            'name'=>$request->name,
            'username'=>$request->username,
            'email'=>$request->email,
            'password'=>Hash::make($request->password),
        ]);

        auth()->attempt($request->only('email','password'));

        return redirect()->route('admin.dashboard');
    }

   
    public function destroy(Request $request)
    {
        auth()->logout();
        
        return redirect()->route('home')->with($notification);
    }
}

