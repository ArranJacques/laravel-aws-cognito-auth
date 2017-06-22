## Laravel AWS Cognito Auth

A simple authentication package for Laravel 5 for authenticating users in Amazon Cognito User Pools.

- [Installation and Setup](#installation-and-setup)
    - [Install](#install)
    - [Configure](#configure)
- [Usage](#usage)
    - [Authenticating](#authenticating)
    - [Handling Failed Authentication](#handling-failed-authentication)
        - [No Error Handling](#no-error-handling)
        - [Throw Exception](#throw-exception)
        - [Return Attempt Instance](#return-attempt-instance)
        - [Using a Closure](#using-a-closure)
        - [About AuthAttemptException](#about-authattemptexception)

This is package works with Laravel's native authentication system and allows the authentication of users that are already registered in Amazon Cognito User Pools. It does not provide functionality for user management, i.e., registering user's into User Pools, password resets, etc.

## Installation and Setup

This package makes use of the  [aws-sdk-php-laravel](https://github.com/aws/aws-sdk-php-laravel) package. As well as setting up and configuring this package you'll also need to configure [aws-sdk-php-laravel](https://github.com/aws/aws-sdk-php-laravel) for the authentication to work. Instructions on how to do this are below. If you've already installed, set up and configured [aws-sdk-php-laravel](https://github.com/aws/aws-sdk-php-laravel) you can skip the parts where it's mentioned below.

### Install

Add `pallant/laravel-aws-cognito-auth` to `composer.json` and run `composer update` to pull down the latest version:

```
"pallant/laravel-aws-cognito-auth": "~1.*"
```

Or use `composer require`:

```
composer require pallant/laravel-aws-cognito-auth
```

Add the service provider and the [aws-sdk-php-laravel](https://github.com/aws/aws-sdk-php-laravel) service provider to the `providers` array in `config/app.php`.

```php
'providers' => [
    ...
    Aws\Laravel\AwsServiceProvider::class,
    Pallant\LaravelAwsCognitoAuth\ServiceProvider::class,
    ...
]
````

Open `app/Http/Kernel.php` and replace the default `\Illuminate\Session\Middleware\AuthenticateSession::class` middleware with `\Pallant\LaravelAwsCognitoAuth\AuthenticateSession::class`.

```php
protected $middlewareGroups = [
    'web' => [
        ...
        \Pallant\LaravelAwsCognitoAuth\AuthenticateSession::class,
        ...
    ],
];
```

Publish the config file as well as the [aws-sdk-php-laravel](https://github.com/aws/aws-sdk-php-laravel) config file to your `config` directory by running:

```
php artisan vendor:publish --provider="Pallant\LaravelAwsCognitoAuth\ServiceProvider"

php artisan vendor:publish --provider="Aws\Laravel\AwsServiceProvider"
```

### Configure

Open `config/auth.php` and set your default guard's driver to `aws-cognito`. Out of the box the default guard is `web` so your `config/auth.php` would look something like:

```php
'defaults' => [
    'guard' => 'web',
    'passwords' => 'users',
],

...

'guards' => [
    'web' => [
        'driver' => 'aws-cognito',
        'provider' => 'users',
    ],
]

```

Open `config/aws-cognito-auth.php` and add your AWS Cognito User Pool's id, and User Pool App's `client-id`.

```php
'pool-id' => '<xxx-xxxxx>',

...

'apps' => [
    'default' => [
        'client-id' => '<xxxxxxxxxx>',
        'refresh-token-expiration' => 30,
    ],
]
```

When creating an App for your User Pool the default Refresh Token Expiration time is 30 days. If you've set a different expiration time for your App then make sure you update the `refresh-token-expiration` value in the config file accordingly.

```php
'apps' => [
    'default' => [
        'client-id' => '<xxxxxxxxxx>',
        'refresh-token-expiration' => <num-of-days>,
    ],
]
```


In the `config/aws-cognito-auth.php` file the `username-attribute` value defines what attribute of your `User` model corresponds to a user's username in your User Pool. By default the package assumes the user's email address is also their username within your User Pool. If you are using a different value as the username within the User Pool then update the `username-attribute` accordingly.

Open the `config/aws.php` file and set the `region` value to whatever region your User Pool is in. The default `config/aws.php` file that is created when using the `php artisan vendor:publish --provider="Aws\Laravel\AwsServiceProvider"` command doesn't include the IAM credential properties so you'll need to add them manually. Add the following to the `config/aws.php` file where `key` is an IAM user Access Key Id and `secret` is the corresponding Secret key:

```php
'credentials' => [
    'key' => <xxxxxxxxxx>,
    'secret' => <xxxxxxxxxx>,
]
```

Your final `config/aws.php` should look something like this:

```php
'credentials' => [
    'key' => <xxxxxxxxxx>,
    'secret' => <xxxxxxxxxx>,
],
'region' => <xx-xxxx-x>,
'version' => 'latest',
'ua_append' => [
    'L5MOD/' . AwsServiceProvider::VERSION,
],
```

## Usage

Once installed and configured authentication works the same as it doesn natively in Laravel. See Laravel's [documentation](https://laravel.com/docs/5.4/authentication) for full details.

### Authenticating

**Authenticate:**

```php
Auth::attempt([
    'email' => 'xxxxx@xxxxx.xx',
    'password' => 'xxxxxxxxxx',
]);
```

**Authenticate and remember:**

```php
Auth::attempt([
    'email' => 'xxxxx@xxxxx.xx',
    'password' => 'xxxxxxxxxx',
], true);
```

**Get the authenticated user:**

```php
Auth::user();
```

**Logout:**

```php
Auth::logout();
```

As well as the default functionality some extra methods are made available for accessing the user's Cognito access token, id token, etc:

```php
Auth::getCognitoAccessToken();
```

```php
Auth::getCognitoIdToken();
```

```php
Auth::getCognitoRefreshToken();
```

```php
Auth::getCognitoTokensExpiryTime();
```

```php
Auth::getCognitoRefreshTokenExpiryTime();
```

### Handling Failed Authentication

AWS Cognito may fail to authenticate for a number of reasons, from simply entering the wrong credentials, or because additional checks or actions are required before the user can be successfully authenticated.

So that you can deal with failed attempts appropriately several options are available to you within the package that dictate how failed attempts should be handled. You can specify how failed attempts should be handled by passing an additional `$errorHandler` argument when calling the `Auth::attempt()` and `Auth::validate()` methods.

```php
Auth::attempt(array $credentials, [bool $remember], [$errorHandler]);

Auth::validate(array $credentials, [$errorHandler]);
```

#### No Error Handling

If an `$errorHandler` isn't passed then all failed authentication attempts will be handled and suppressed internally, and both the `Auth::attempt()` and `Auth::validate()` methods will simply return `true` or `false` as to whether the authentication attempt was successful.

#### Throw Exception

To have the `Auth::attempt()` and `Auth::validate()` methods throw an exception pass `AWS_COGNITO_AUTH_THROW_EXCEPTION` as the `$errorHandler` argument.

```php
Auth::attempt([
    'email' => 'xxxxx@xxxxx.xx',
    'password' => 'xxxxxxxxxx',
], false, AWS_COGNITO_AUTH_THROW_EXCEPTION);

Auth::validate([
    'email' => 'xxxxx@xxxxx.xx',
    'password' => 'xxxxxxxxxx',
], AWS_COGNITO_AUTH_THROW_EXCEPTION);
```

If the authentication fails then an `\Pallant\LaravelAwsCognitoAuth\AuthAttemptException` will be thrown, which can be used to access the underlying error by calling the exception's `getResponse()` method. [About AuthAttemptException](#about-authattemptexception).

```php
try {
    Auth::attempt([
        'email' => 'xxxxx@xxxxx.xx',
        'password' => 'xxxxxxxxxx',
    ], false, AWS_COGNITO_AUTH_THROW_EXCEPTION);
} catch (\Exception $e) {
    $response = $e->getResponse();
    // Handle error...
}
```

#### Return Attempt Instance

To have the `Auth::attempt()` and `Auth::validate()` methods return an attempt object pass `AWS_COGNITO_AUTH_RETURN_ATTEMPT` as the `$errorHandler` argument.

```php
Auth::attempt([
    'email' => 'xxxxx@xxxxx.xx',
    'password' => 'xxxxxxxxxx',
], false, AWS_COGNITO_AUTH_RETURN_ATTEMPT);

Auth::validate([
    'email' => 'xxxxx@xxxxx.xx',
    'password' => 'xxxxxxxxxx',
], AWS_COGNITO_AUTH_RETURN_ATTEMPT);
```

When using `AWS_COGNITO_AUTH_RETURN_ATTEMPT` both methods will return an instance of `\Pallant\LaravelAwsCognitoAuth\AuthAttempt`, which can be used to check if the authentication attempt was successful or not.

```php
$attempt = Auth::attempt([
    'email' => 'xxxxx@xxxxx.xx',
    'password' => 'xxxxxxxxxx',
], false, AWS_COGNITO_AUTH_RETURN_ATTEMPT);

if ($attempt->successful()) {
    // Do something...
} else {
    $response = $attempt->getResponse();
    // Handle error...
}
```

For unsuccessful authentication attempts the attempt instance's `getResponse()` method can be used to access the underlying error. This method will return an array of data and depending on the reason why the authentication attempt failed the array will contain different values.

In events where the AWS Cognito API has thrown an exception, such as when invalid credentials are used, the array that is returned will contain the original exception.

```php
[
    'exception' => CognitoIdentityProviderException {...},
]
```

In events where the AWS Cognito API has failed to authenticate for some other reason, for example because a challenge must be passed, then the array that is returned will contain the details of the error.

```php
[
    'ChallengeName' => 'NEW_PASSWORD_REQUIRED',
    'Session' => '...',
    'ChallengeParameters' => [...],
]
```

#### Using a Closure

To handle failed authentication attempts with a closure pass one as the `Auth::attempt()` and `Auth::validate()` methods' `$errorHandler` argument.

```php
Auth::attempt([
    'email' => 'xxxxx@xxxxx.xx',
    'password' => 'xxxxxxxxxx',
], false, function (\Pallant\LaravelAwsCognitoAuth\AuthAttemptException $e) {
    $response = $e->getResponse();
    // Handle error...
});

Auth::validate([
    'email' => 'xxxxx@xxxxx.xx',
    'password' => 'xxxxxxxxxx',
], function (\Pallant\LaravelAwsCognitoAuth\AuthAttemptException $e) {
    $response = $e->getResponse();
    // Handle error...
};
```

If the authentication fails then the closure will be run and will be passed an `\Pallant\LaravelAwsCognitoAuth\AuthAttemptException` instance, which can be used to access the underlying error by calling the exception's `getResponse()` method. [About AuthAttemptException](#about-authattemptexception).

#### About AuthAttemptException

An `\Pallant\LaravelAwsCognitoAuth\AuthAttemptException` exception will be thrown when using the `AWS_COGNITO_AUTH_THROW_EXCEPTION` error handler, or will be passed as an argument to a closure when using the `Clousre` method of error handling.

The `\Pallant\LaravelAwsCognitoAuth\AuthAttemptException::getResponse()` method will return an array of data and depending on the reason why the authentication attempt failed the array will contain different values.

In events where the AWS Cognito API has thrown an exception, such as when invalid credentials are used, the array that is returned will contain the original exception.

```php
[
    'exception' => CognitoIdentityProviderException {...},
]
```

In events where the AWS Cognito API has failed to authenticate for some other reason, for example because a challenge must be passed, the array that is returned will contain the details of the error.

```php
[
    'ChallengeName' => 'NEW_PASSWORD_REQUIRED',
    'Session' => '...',
    'ChallengeParameters' => [...],
]
```
