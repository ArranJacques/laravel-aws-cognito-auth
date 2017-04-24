<?php

namespace Pallant\LaravelAwsCognitoAuth;

class Recaller
{
    /**
     * The "recaller" / "remember me" cookie string.
     *
     * @var string
     */
    protected $recaller;

    /**
     * Create a new recaller instance.
     *
     * @param string $recaller
     */
    public function __construct($recaller)
    {
        $this->recaller = json_decode($recaller);
    }

    /**
     * Get the user ID from the recaller.
     *
     * @return string
     */
    public function id()
    {
        return $this->recaller->id;
    }

    /**
     * Get the "remember token" token from the recaller.
     *
     * @return string
     */
    public function token()
    {
        return $this->recaller->rememberToken;
    }

    /**
     * Get the AWS Cognito refresh token from the recaller.
     *
     * @return null|string
     */
    public function cognitoRefreshToken()
    {
        $refreshToken = isset($this->recaller->cognitoRefreshToken) ? $this->recaller->cognitoRefreshToken : null;

        $expDate = $this->cognitoRefreshTokenExpTime();

        if (is_null($expDate) OR $expDate < time()) {
            return null;
        }

        return $refreshToken;
    }

    /**
     * Get the expiry date/time of AWS Cognito refresh token from the recaller.
     *
     * @return null|string
     */
    public function cognitoRefreshTokenExpTime()
    {
        return isset($this->recaller->cognitoRefreshTokenExp) ?
            $this->recaller->cognitoRefreshTokenExp :
            null;
    }

    /**
     * Determine if the recaller is valid.
     *
     * @return bool
     */
    public function valid()
    {
        return
            isset($this->recaller->id) AND
            isset($this->recaller->rememberToken);
    }

}
