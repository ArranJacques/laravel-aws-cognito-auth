<?php

namespace Pallant\LaravelAwsCognitoAuth;

class AuthAttempt
{
    /**
     * @var bool
     */
    protected $successful;

    /**
     * @var array
     */
    protected $response = [];

    /**
     * AuthAttempt constructor.
     *
     * @param bool $successful
     * @param array $response
     */
    public function __construct($successful, array $response = [])
    {
        $this->successful = $successful;
        $this->response = $response;
    }

    /**
     * Was the authentication attempt successful.
     *
     * @return bool
     */
    public function successful()
    {
        return $this->successful;
    }

    /**
     * Get the response data from an unsuccessful authentication attempt.
     *
     * @return array|null
     */
    public function getResponse()
    {
        return $this->response;
    }

}
