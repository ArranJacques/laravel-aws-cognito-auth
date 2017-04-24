## Laravel AWS Cognito Auth

A simple authentication package for Laravel 5 for authenticating users in Amazon Cognito User Pools.

This is package works with Laravel's native authentication system and allows the authentication of users that are already registered in Amazon Cognito User Pools. It does not provide functionality for user management, i.e., registering user's into User Pools, password resets, etc.

## Installation and Setup

This package makes use of the  [aws-sdk-php-laravel](https://github.com/aws/aws-sdk-php-laravel) package. As well as setting up and configuring this package you'll also need to configure [aws-sdk-php-laravel](https://github.com/aws/aws-sdk-php-laravel) for the authentication to work. Instructions on how to do this are below. If you've already installed, set up and configured [aws-sdk-php-laravel](https://github.com/aws/aws-sdk-php-laravel) you can skip the parts where it's mentioned below.

### Install

Add `pallant/laravel-aws-cognito-auth` to `composer.json` and run `composer update` to pull down the latest version:

```
"pallant/laravel-aws-cognito-auth": "~1.0"
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

Once installed and configured authentication works in exactly the same way as it does natively is Laravel. See Laravel's [documentation](https://laravel.com/docs/5.4/authentication) for full details.

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