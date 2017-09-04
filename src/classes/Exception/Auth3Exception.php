<?php

namespace Auth3\Exception;

class Auth3Exception extends \League\OAuth2\Server\Exception\OAuthServerException {

	/**
     * @var int
     */
    private $httpStatusCode;

    /**
     * @var string
     */
    private $errorType;

    /**
     * @var null|string
     */
    private $hint;

    /**
     * @var null|string
     */
    private $redirectUri;

    /**
     * Invalid Two-Factor auth code.
     *
     * @return static
     */
    public static function invalidTwoFactor()
    {
        $errorMessage = 'The provided two-factor authorization code was not valid.';
        $hint = 'Make sure you have copied the code correctly.';

        return new static($errorMessage, 11, 'invalid_twofactor', 401, $hint);
    }

}