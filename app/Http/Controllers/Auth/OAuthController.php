<?php

namespace App\Http\Controllers\Auth;

use App\Extensions\OAuth\OAuthService;
use App\Filament\Pages\Auth\EditProfile;
use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\Setting;
use App\Services\Users\UserUpdateService;
use Exception;
use Filament\Notifications\Notification;
use Illuminate\Auth\AuthManager;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;

class OAuthController extends Controller
{
    public function __construct(
        private readonly AuthManager $auth,
        private readonly UserUpdateService $updateService,
        private readonly OAuthService $oauthService
    ) {}

    /**
     * Redirect user to the OAuth provider
     */
    public function redirect(string $driver): RedirectResponse
    {
        // Driver is disabled - redirect to normal login
        if (!$this->oauthService->get($driver)->isEnabled()) {
            return redirect()->route('auth.login');
        }

        return Socialite::with($driver)->redirect();
    }

    /**
     * Callback from OAuth provider.
     */
    public function callback(Request $request, string $driver): RedirectResponse
    {
        // Driver is disabled - redirect to normal login
        if (!$this->oauthService->get($driver)?->isEnabled()) {
            return redirect()->route('auth.login');
        }

        // Check for errors (https://www.oauth.com/oauth2-servers/server-side-apps/possible-errors/)
        if ($request->get('error')) {
            report($request->get('error_description') ?? $request->get('error'));

            Notification::make()
                ->title('Something went wrong')
                ->body($request->get('error'))
                ->danger()
                ->persistent()
                ->send();

            return redirect()->route('auth.login');
        }

        $oauthUser = Socialite::driver($driver)->user();

        // User is already logged in and wants to link a new OAuth Provider
        if ($request->user()) {
            $oauth = $request->user()->oauth;
            $oauth[$driver] = $oauthUser->getId();

            $this->updateService->handle($request->user(), ['oauth' => $oauth]);

            return redirect(EditProfile::getUrl(['tab' => '-oauth-tab'], panel: 'app'));
        }

        try {
            $user = User::query()->whereJsonContains('oauth->'. $driver, $oauthUser->getId())->firstOrFail();

            $this->auth->guard()->login($user, true);
        } catch (Exception) {
            $autocreate = $request->input('autocreate', false);

            if ($autocreate) {
                // Autocreate user as before
                $userData = [
                    'email' => $oauthUser->getEmail(),
                    'username' => $oauthUser->getNickname() ?? $oauthUser->getName(),
                    'oauth' => [
                        $driver => $oauthUser->getId(),
                    ],
                ];
            
                $user = app(\App\Services\Users\UserCreationService::class)->handle($userData);
                $this->auth->guard()->login($user, true);
                return redirect('/');
            }
        
            // Otherwise, notify and redirect to login (or return JSON for frontend)
            if ($request->expectsJson()) {
                // Let frontend know autocreation is possible
                return response()->json([
                    'error' => 'No linked User found',
                    'autocreate_available' => true,
                ], 404);
            }
        
            Notification::make()
                ->title('No linked User found')
                ->danger()
                ->persistent()
                ->send();
        
            return redirect()->route('auth.login');
        }
    }
}
