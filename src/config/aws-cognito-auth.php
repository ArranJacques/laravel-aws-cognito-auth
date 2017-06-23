<?php

return [

    /*
    |--------------------------------------------------------------------------
    | User Pool ID
    |--------------------------------------------------------------------------
    |
    | This is the ID of your AWS Cognito User Pool.
    |
    */

    'pool-id' => env('AWS_COGNITO_IDENTITY_POOL_ID', ''),

    /*
    |--------------------------------------------------------------------------
    | Default Authentication Error Handler
    |--------------------------------------------------------------------------
    |
    | A Default error handler for handling failed authentication attempts.
    | See docs for available options.
    |
    */

    'errors' => [
        'handler' => null,
    ],


    /*
    |--------------------------------------------------------------------------
    | User Pool Username
    |--------------------------------------------------------------------------
    |
    | This is the attribute on your User model that corresponds to the user's
    | username in your User Pool.
    |
    */

    'username-attribute' => 'email',

    /*
    |--------------------------------------------------------------------------
    | Default User Pool Application
    |--------------------------------------------------------------------------
    |
    | Here you can define the default application to use when making api calls
    | to the User Pool
    |
    */

    'app' => 'default',

    /*
    |--------------------------------------------------------------------------
    | User Pool Applications
    |--------------------------------------------------------------------------
    |
    | Here you can define the details of your applications through which the
    | User Pool will be accessed.
    |
    */

    'apps' => [

        'default' => [
            'client-id' => env('AWS_COGNITO_IDENTITY_APP_CLIENT_ID', ''),
            'refresh-token-expiration' => 30,
        ],

    ],

];
