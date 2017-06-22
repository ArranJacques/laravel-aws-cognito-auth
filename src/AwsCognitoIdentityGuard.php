<?php

namespace Pallant\LaravelAwsCognitoAuth;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Carbon\Carbon;
use Closure;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Cookie\QueueingFactory as CookieJar;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Str;
use RuntimeException;
use Symfony\Component\HttpFoundation\Request;

class AwsCognitoIdentityGuard implements StatefulGuard
{
    use GuardHelpers;

    /**
     * The name of the Guard. Typically "session".
     * Corresponds to guard name in authentication configuration.
     *
     * @var string
     */
    protected $name;

    /**
     * An instance of the AWS Cognito provider client.
     *
     * @var CognitoIdentityProviderClient
     */
    protected $client;

    /**
     * The user we last attempted to retrieve.
     *
     * @var \Illuminate\Contracts\Auth\Authenticatable
     */
    protected $lastAttempted;

    /**
     * Indicates if the user was authenticated via a recaller cookie.
     *
     * @var bool
     */
    protected $viaRemember = false;

    /**
     * The session used by the guard.
     *
     * @var \Illuminate\Contracts\Session\Session
     */
    protected $session;

    /**
     * The Illuminate cookie creator service.
     *
     * @var \Illuminate\Contracts\Cookie\QueueingFactory
     */
    protected $cookie;

    /**
     * The request instance.
     *
     * @var \Symfony\Component\HttpFoundation\Request
     */
    protected $request;

    /**
     * @var array
     */
    protected $config;

    /**
     * The event dispatcher instance.
     *
     * @var \Illuminate\Contracts\Events\Dispatcher
     */
    protected $events;

    /**
     * Indicates if the logout method has been called.
     *
     * @var bool
     */
    protected $loggedOut = false;

    /**
     * Indicates if a token user retrieval has been attempted.
     *
     * @var bool
     */
    protected $recallAttempted = false;

    /**
     * @var array
     */
    protected $cognitoTokens = null;

    /**
     * Create a new authentication guard.
     *
     * @param string $name
     * @param \Aws\CognitoIdentityProvider\CognitoIdentityProviderClient $client
     * @param \Illuminate\Contracts\Auth\UserProvider $provider
     * @param \Illuminate\Contracts\Session\Session $session
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param array $config
     */
    public function __construct(
        $name,
        CognitoIdentityProviderClient $client,
        UserProvider $provider,
        Session $session,
        Request $request = null,
        array $config = []
    ) {
        $this->name = $name;
        $this->client = $client;
        $this->session = $session;
        $this->request = $request;
        $this->provider = $provider;
        $this->config = $config;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if ($this->loggedOut) {
            return null;
        }

        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (!is_null($this->user)) {
            return $this->user;
        }

        $id = $this->session->get($this->getName());

        // First we will try to load the user using the identifier in the session if
        // one exists. Otherwise we will check for a "remember me" cookie in this
        // request, and if one exists, attempt to retrieve the user using that.
        $user = null;

        if (!is_null($id) AND $user = $this->provider->retrieveById($id)) {

            if (!$tokens = $this->getCognitoTokens()) {
                return null;
            }

            $this->fireAuthenticatedEvent($user);
        }

        // If the user is null, but we decrypt a "recaller" cookie we can attempt to
        // pull the user data on that cookie which serves as a remember cookie on
        // the application. Once we have a user we can return it to the caller.
        $recaller = $this->recaller();

        if (is_null($user) AND !is_null($recaller)) {

            $user = $this->userFromRecaller($recaller);

            if ($user) {

                if (!$cognitoTokens = $this->cognitoTokensFromRecaller($recaller)) {
                    return null;
                }

                $this->updateSession($user->getAuthIdentifier());

                $this->storeCognitoTokens($cognitoTokens);

                $this->fireLoginEvent($user, true);
            }
        }

        return $this->user = $user;
    }

    /**
     * Pull a user from the repository by its "remember me" cookie token.
     *
     * @param Recaller $recaller
     * @return mixed
     */
    protected function userFromRecaller($recaller)
    {
        if (!$recaller->valid() OR $this->recallAttempted) {
            return null;
        }

        // If the user is null, but we decrypt a "recaller" cookie we can attempt to
        // pull the user data on that cookie which serves as a remember cookie on
        // the application. Once we have a user we can return it to the caller.
        $this->recallAttempted = true;

        $this->viaRemember = !is_null($user = $this->provider->retrieveByToken(
            $recaller->id(), $recaller->token()
        ));

        return $user;
    }

    /**
     * Get a user's cognito tokens from their "remember me" cookie.
     *
     * @param Recaller $recaller
     * @return null|array
     */
    protected function cognitoTokensFromRecaller($recaller)
    {
        if (!$recaller->valid() OR !$refreshToken = $recaller->cognitoRefreshToken()) {
            return null;
        }

        if (!$tokens = $this->refreshCognitoTokens($refreshToken)) {
            return null;
        }

        $tokens = $this->addTokenExpiryTimes($tokens, false);
        $tokens['RefreshToken'] = $refreshToken;
        $tokens['RefreshTokenExpires'] = $recaller->cognitoRefreshTokenExpTime();

        $this->cognitoTokens = $tokens;

        $this->storeCognitoTokens($this->cognitoTokens);

        return $this->cognitoTokens;
    }

    /**
     * Get the decrypted recaller cookie for the request.
     *
     * @return \Pallant\LaravelAwsCognitoAuth\Recaller|null
     */
    protected function recaller()
    {
        if (is_null($this->request)) {
            return null;
        }

        if ($recaller = $this->request->cookies->get($this->getRecallerName())) {
            return new Recaller($recaller);
        }

        return null;
    }

    /**
     * Get the user's AWS Cognito access, id and refresh tokens.
     *
     * @return null|array
     */
    protected function getCognitoTokens()
    {
        if ($this->cognitoTokens) {
            return $this->cognitoTokens;
        }

        $tokens = $this->session->get($this->getCognitoTokensName());

        if (!$tokens) {
            return null;
        }

        $now = time();

        // If the access and/or id tokens have expired then we'll want to request new
        // ones using the refresh token.
        if ($tokens['ExpiresIn'] < $now) {

            // If the refresh token has also expired then we're unable to request new
            // tokens.
            if ($tokens['RefreshTokenExpires'] < $now) {
                return null;
            }

            if (!$tokens = $this->refreshCognitoTokens($tokens['RefreshToken'])) {
                return null;
            }

            $tokens = $this->addTokenExpiryTimes($tokens, false);

            $this->storeCognitoTokens($tokens);
        }

        $this->cognitoTokens = $tokens;

        return $this->cognitoTokens;
    }

    /**
     * Refresh the user's AWS Cognito tokens.
     *
     * @param string $refreshToken
     * @return null|array
     */
    protected function refreshCognitoTokens($refreshToken)
    {
        try {

            $response = $this->client->adminInitiateAuth([
                'AuthFlow' => 'REFRESH_TOKEN_AUTH',
                'AuthParameters' => [
                    'REFRESH_TOKEN' => $refreshToken,
                ],
                'ClientId' => $this->getDefaultAppConfig()['client-id'],
                'UserPoolId' => $this->config['pool-id'],
            ]);

        } catch (CognitoIdentityProviderException $e) {
            return null;
        }

        return $response['AuthenticationResult'];
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|null
     */
    public function id()
    {
        if ($this->loggedOut) {
            return null;
        }

        return $this->user()
            ? $this->user()->getAuthIdentifier()
            : $this->session->get($this->getName());
    }

    /**
     * Log a user into the application without sessions or cookies.
     *
     * @param array $credentials
     * @return bool
     */
    public function once(array $credentials = [])
    {
        $this->fireAttemptEvent($credentials);

        if ($this->validate($credentials)) {

            $this->setUser($this->lastAttempted);

            return true;
        }

        return false;
    }

    /**
     * Log the given user ID into the application without sessions or cookies.
     *
     * @param mixed $id
     * @return \Illuminate\Contracts\Auth\Authenticatable|false
     */
    public function onceUsingId($id)
    {
        if (!is_null($user = $this->provider->retrieveById($id))) {

            $this->setUser($user);

            return $user;
        }

        return false;
    }

    /**
     * Validate a user's credentials.
     *
     * @param array $credentials
     * @param mixed $errorHandler
     * @return bool|\Pallant\LaravelAwsCognitoAuth\AuthAttempt
     */
    public function validate(array $credentials = [], $errorHandler = null)
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        $response = $this->attemptCognitoAuthentication($credentials);

        if ($response->successful()) {
            return $errorHandler == AWS_COGNITO_AUTH_RETURN_ATTEMPT ? $response : true;
        }

        if ($errorHandler == AWS_COGNITO_AUTH_THROW_EXCEPTION) {
            throw new AuthAttemptException($response);
        } elseif ($errorHandler == AWS_COGNITO_AUTH_RETURN_ATTEMPT) {
            return $response;
        } elseif ($errorHandler instanceof Closure) {
            $errorHandler(new AuthAttemptException($response));
        }

        return false;
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param array $credentials
     * @param bool $remember
     * @param mixed $errorHandler
     * @return bool|\Pallant\LaravelAwsCognitoAuth\AuthAttempt
     */
    public function attempt(array $credentials = [], $remember = false, $errorHandler = null)
    {
        $this->fireAttemptEvent($credentials, $remember);

        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        // If an implementation of UserInterface was returned we'll attempt to
        // authenticate with AWS Cognito.
        $response = $this->attemptCognitoAuthentication($credentials);

        // If the authentication attempt was successful then log the user into the
        // application and return an appropriate response.
        if ($response->successful()) {

            $this->cognitoTokens = $this->addTokenExpiryTimes($response->getResponse()['AuthenticationResult']);

            $this->storeCognitoTokens($this->cognitoTokens);

            $this->login($user, $remember);

            return $errorHandler == AWS_COGNITO_AUTH_RETURN_ATTEMPT ? $response : true;
        }

        // If the authentication attempt fails we will fire an event so that the user
        // may be notified of any suspicious attempts to access their account from
        // an unrecognized user. A developer may listen to this event as needed.
        $this->fireFailedEvent($user, $credentials);

        if ($errorHandler == AWS_COGNITO_AUTH_THROW_EXCEPTION) {
            throw new AuthAttemptException($response);
        } elseif ($errorHandler == AWS_COGNITO_AUTH_RETURN_ATTEMPT) {
            return $response;
        } elseif ($errorHandler instanceof Closure) {
            $errorHandler(new AuthAttemptException($response));
        }

        return false;
    }

    /**
     * Add expiry date/times to a user's AWS Congnito tokens.
     *
     * @param array $tokens
     * @param bool $updateRefreshTokenExp
     * @return array
     */
    protected function addTokenExpiryTimes(array $tokens, $updateRefreshTokenExp = true)
    {
        $tokens['ExpiresIn'] = Carbon::now()->addSeconds($tokens['ExpiresIn'] - 10)->timestamp;

        $days = $this->getDefaultAppConfig()['refresh-token-expiration'];

        if ($updateRefreshTokenExp) {
            $tokens['RefreshTokenExpires'] = Carbon::now()->addDays($days)->timestamp;
        }

        return $tokens;
    }

    /**
     * Store the tokens returned from a successful auth attempt in the session.
     *
     * @param array $tokens
     */
    protected function storeCognitoTokens(array $tokens)
    {
        $this->session->put($this->getCognitoTokensName(), $tokens);
    }

    /**
     * Attempt to authenticate with AWS Cognito.
     *
     * @param array $credentials
     * @return \Pallant\LaravelAwsCognitoAuth\AuthAttempt
     */
    protected function attemptCognitoAuthentication(array $credentials)
    {
        if (
            !$username = array_get($credentials, $this->config['username-attribute']) OR
            !$password = array_get($credentials, 'password')
        ) {
            return new AuthAttempt(false);
        }

        try {

            $response = $this->client->adminInitiateAuth([
                'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
                'AuthParameters' => [
                    'USERNAME' => $username,
                    'PASSWORD' => $password,
                ],
                'ClientId' => $this->getDefaultAppConfig()['client-id'],
                'UserPoolId' => $this->config['pool-id'],
            ]);

            return new AuthAttempt(!!$response['AuthenticationResult'], $response->toArray());

        } catch (CognitoIdentityProviderException $e) {
            return new AuthAttempt(false, ['exception' => $e]);
        }
    }

    /**
     * Log the given user ID into the application.
     *
     * @param mixed $id
     * @param bool $remember
     * @return \Illuminate\Contracts\Auth\Authenticatable|false
     */
    public function loginUsingId($id, $remember = false)
    {
        if (!is_null($user = $this->provider->retrieveById($id))) {

            $this->login($user, $remember);

            return $user;
        }

        return false;
    }

    /**
     * Log a user into the application.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @param bool $remember
     * @return void
     */
    public function login(AuthenticatableContract $user, $remember = false)
    {
        $this->updateSession($user->getAuthIdentifier());

        // If the user should be permanently "remembered" by the application we will
        // queue a permanent cookie that contains the encrypted copy of the user
        // identifier. We will then decrypt this later to retrieve the users.
        if ($remember) {

            $this->ensureRememberTokenIsSet($user);

            $this->queueRecallerCookie($user, $this->cognitoTokens);
        }

        // If we have an event dispatcher instance set we will fire an event so that
        // any listeners will hook into the authentication events and run actions
        // based on the login and logout events fired from the guard instances.
        $this->fireLoginEvent($user, $remember);

        $this->setUser($user);
    }

    /**
     * Update the session with the given ID.
     *
     * @param string $id
     * @return void
     */
    protected function updateSession($id)
    {
        $this->session->put($this->getName(), $id);

        $this->session->migrate(true);
    }

    /**
     * Create a new "remember me" token for the user if one doesn't already exist.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @return void
     */
    protected function ensureRememberTokenIsSet(AuthenticatableContract $user)
    {
        if (empty($user->getRememberToken())) {
            $this->cycleRememberToken($user);
        }
    }

    /**
     * Queue the recaller cookie into the cookie jar.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @param array|null $cognitoTokens
     * @return void
     */
    protected function queueRecallerCookie(AuthenticatableContract $user, array $cognitoTokens = null)
    {
        $data = [
            'id' => $user->getAuthIdentifier(),
            'rememberToken' => $user->getRememberToken(),
            'cognitoRefreshToken' => $cognitoTokens['RefreshToken'],
            'cognitoRefreshTokenExp' => $cognitoTokens['RefreshTokenExpires'],
        ];

        $this->getCookieJar()->queue($this->createRecaller(json_encode($data)));
    }

    /**
     * Create a "remember me" cookie for a given ID.
     *
     * @param string $value
     * @return \Symfony\Component\HttpFoundation\Cookie
     */
    protected function createRecaller($value)
    {
        return $this->getCookieJar()->forever($this->getRecallerName(), $value);
    }

    /**
     * Log the user out of the application.
     *
     * @return void
     */
    public function logout()
    {
        $user = $this->user();

        // If we have an event dispatcher instance, we can fire off the logout event
        // so any further processing can be done. This allows the developer to be
        // listening for anytime a user signs out of this application manually.
        $this->clearUserDataFromStorage();

        if (!is_null($this->user)) {
            $this->cycleRememberToken($user);
        }

        if (isset($this->events)) {
            $this->events->dispatch(new Logout($user));
        }

        // Once we have fired the logout event we will clear the users out of memory
        // so they are no longer available as the user is no longer considered as
        // being signed into this application and should not be available here.
        $this->user = null;

        $this->cognitoTokens = null;

        $this->loggedOut = true;
    }

    /**
     * Remove the user data from the session and cookies.
     *
     * @return void
     */
    protected function clearUserDataFromStorage()
    {
        $this->session->remove($this->getName());
        $this->session->remove($this->getCognitoTokensName());

        if (!is_null($this->recaller())) {
            $this->getCookieJar()->queue($this->getCookieJar()
                ->forget($this->getRecallerName()));
        }
    }

    /**
     * Refresh the "remember me" token for the user.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @return void
     */
    protected function cycleRememberToken(AuthenticatableContract $user)
    {
        $user->setRememberToken($token = Str::random(60));

        $this->provider->updateRememberToken($user, $token);
    }

    /**
     * Register an authentication attempt event listener.
     *
     * @param mixed $callback
     * @return void
     */
    public function attempting($callback)
    {
        if (isset($this->events)) {
            $this->events->listen(Attempting::class, $callback);
        }
    }

    /**
     * Fire the attempt event with the arguments.
     *
     * @param array $credentials
     * @param bool $remember
     * @return void
     */
    protected function fireAttemptEvent(array $credentials, $remember = false)
    {
        if (isset($this->events)) {
            $this->events->dispatch(new Attempting(
                $credentials, $remember
            ));
        }
    }

    /**
     * Fire the login event if the dispatcher is set.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @param bool $remember
     * @return void
     */
    protected function fireLoginEvent($user, $remember = false)
    {
        if (isset($this->events)) {
            $this->events->dispatch(new Login($user, $remember));
        }
    }

    /**
     * Fire the authenticated event if the dispatcher is set.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @return void
     */
    protected function fireAuthenticatedEvent($user)
    {
        if (isset($this->events)) {
            $this->events->dispatch(new Authenticated($user));
        }
    }

    /**
     * Fire the failed authentication attempt event with the given arguments.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable|null $user
     * @param array $credentials
     * @return void
     */
    protected function fireFailedEvent($user, array $credentials)
    {
        if (isset($this->events)) {
            $this->events->dispatch(new Failed($user, $credentials));
        }
    }

    /**
     * Get the last user we attempted to authenticate.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function getLastAttempted()
    {
        return $this->lastAttempted;
    }

    /**
     * Get the authenticated user's AWS Cognito access token.
     *
     * @return string
     */
    public function getCognitoAccessToken()
    {
        return array_get($this->cognitoTokens, 'AccessToken');
    }

    /**
     * Get the authenticated user's AWS Cognito id token.
     *
     * @return string
     */
    public function getCognitoIdToken()
    {
        return array_get($this->cognitoTokens, 'IdToken');
    }

    /**
     * Get the authenticated user's AWS Cognito refresh token.
     *
     * @return string
     */
    public function getCognitoRefreshToken()
    {
        return array_get($this->cognitoTokens, 'RefreshToken');
    }

    /**
     * Get the expiry time of the authenticated user's AWS Cognito id and
     * access tokens.
     *
     * @return int
     */
    public function getCognitoTokensExpiryTime()
    {
        return array_get($this->cognitoTokens, 'ExpiresIn');
    }

    /**
     * Get the expiry time of the authenticated user's AWS Cognito refresh token.
     *
     * @return int
     */
    public function getCognitoRefreshTokenExpiryTime()
    {
        return array_get($this->cognitoTokens, 'RefreshTokenExpires');
    }

    /**
     * Get a unique identifier for the auth session value.
     *
     * @return string
     */
    public function getName()
    {
        return 'login_' . $this->name . '_' . sha1(static::class);
    }

    /**
     * Get a unique identifier for the auth tokens session value.
     *
     * @return string
     */
    public function getCognitoTokensName()
    {
        return 'login_' . $this->name . '_aws_tokens_' . sha1(static::class);
    }

    /**
     * Get the name of the cookie used to store the "recaller".
     *
     * @return string
     */
    public function getRecallerName()
    {
        return 'remember_' . $this->name . '_' . sha1(static::class);
    }

    /**
     * Determine if the user was authenticated via "remember me" cookie.
     *
     * @return bool
     */
    public function viaRemember()
    {
        return $this->viaRemember;
    }

    /**
     * Get the cookie creator instance used by the guard.
     *
     * @return \Illuminate\Contracts\Cookie\QueueingFactory
     * @throws \RuntimeException
     */
    public function getCookieJar()
    {
        if (!isset($this->cookie)) {
            throw new RuntimeException('Cookie jar has not been set.');
        }

        return $this->cookie;
    }

    /**
     * Set the cookie creator instance used by the guard.
     *
     * @param \Illuminate\Contracts\Cookie\QueueingFactory $cookie
     * @return void
     */
    public function setCookieJar(CookieJar $cookie)
    {
        $this->cookie = $cookie;
    }

    /**
     * Get the event dispatcher instance.
     *
     * @return \Illuminate\Contracts\Events\Dispatcher
     */
    public function getDispatcher()
    {
        return $this->events;
    }

    /**
     * Set the event dispatcher instance.
     *
     * @param \Illuminate\Contracts\Events\Dispatcher $events
     * @return void
     */
    public function setDispatcher(Dispatcher $events)
    {
        $this->events = $events;
    }

    /**
     * Return the currently cached user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Set the current user.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @return $this
     */
    public function setUser(AuthenticatableContract $user)
    {
        $this->user = $user;

        $this->loggedOut = false;

        $this->fireAuthenticatedEvent($user);

        return $this;
    }

    /**
     * @return array
     */
    protected function getDefaultAppConfig()
    {
        return $this->config['apps'][$this->config['app']];
    }

    /**
     * Get the current request instance.
     *
     * @return \Symfony\Component\HttpFoundation\Request
     */
    public function getRequest()
    {
        return $this->request ?: Request::createFromGlobals();
    }

    /**
     * Set the current request instance.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }

}
