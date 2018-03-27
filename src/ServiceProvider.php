<?php

namespace Pallant\LaravelAwsCognitoAuth;

use Illuminate\Support\ServiceProvider as BaseServiceProvider;

class ServiceProvider extends BaseServiceProvider
{
    /**
     * Boot any authentication / authorization services.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__ . '/config/aws-cognito-auth.php' => config_path('aws-cognito-auth.php'),
        ]);

        $this->registerGuard();

        $this->defineConstants();
    }

    /**
     * Register the AWS Cognito guard.
     */
    protected function registerGuard()
    {
        $this->app['auth']->extend('aws-cognito', function ($app, $name, array $config) {

            $client = $this->app->make('aws')->createCognitoIdentityProvider();

            $provider = $this->app['auth']->createUserProvider($config['provider']);

            $guard = new AwsCognitoIdentityGuard(
                $name,
                $client,
                $provider,
                $this->app['session.store'],
                $this->app['request'],
                $this->app['config']['aws-cognito-auth']
            );

            $guard->setCookieJar($this->app['cookie']);

            $guard->setDispatcher($this->app['events']);

            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));

            return $guard;
        });
    }

    /**
     * Define constants related to the package.
     */
    public function defineConstants()
    {
        if (!defined('AWS_COGNITO_AUTH_THROW_EXCEPTION')) {
            define('AWS_COGNITO_AUTH_THROW_EXCEPTION', 'throw-exception');
        }

        if (!defined('AWS_COGNITO_AUTH_RETURN_ATTEMPT')) {
            define('AWS_COGNITO_AUTH_RETURN_ATTEMPT', 'return-attempt');
        }
    }

}
