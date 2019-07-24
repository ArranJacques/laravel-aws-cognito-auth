<?php

namespace Pallant\LaravelAwsCognitoAuth;

use RuntimeException;

class AuthAttemptException extends RuntimeException
{
    /**
     * @var \Pallant\LaravelAwsCognitoAuth\AuthAttempt
     */
    protected $response;

    /**
     * AuthAttemptException constructor.
     *
     * @param \Pallant\LaravelAwsCognitoAuth\AuthAttempt $response
     */
    public function __construct(AuthAttempt $response)
    {
        $this->response = $response->getResponse();

        parent::__construct('Unable to authenticate', 0, null);
    }

    /**
     * @return array|null
     */
    public function getResponse()
    {
        return $this->response;
    }
}
