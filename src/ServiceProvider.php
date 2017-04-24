<?php

namespace Pallant\LaravelAwsCognitoAuth;

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider;

class ServiceProvider extends AuthServiceProvider
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

        $this->app['auth']->extend('aws-cognito', function (Application $app, $name, array $config) {

            $client = $app->make('aws')->createCognitoIdentityProvider();

            $provider = $app['auth']->createUserProvider($config['provider']);

            $guard = new AwsCognitoIdentityGuard(
                $name,
                $client,
                $provider,
                $app['session.store'],
                $app['request'],
                $app['config']['aws-cognito-auth']
            );

            $guard->setCookieJar($this->app['cookie']);

            $guard->setDispatcher($this->app['events']);

            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));

            return $guard;
        });
    }

}
