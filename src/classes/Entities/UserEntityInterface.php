<?php

namespace Auth3\Entities;

interface UserEntityInterface extends \League\OAuth2\Server\Entities\UserEntityInterface {
	/**
     * Return the user's identifier.
     *
     * @return mixed
     */
    public function getIdentifier();

    /**
	* Return whether or not the user has 2fa enabled
	* @return boolean
    */
    public function hasTwoFactorEnabled();

    /**
	* Return the user's unique gauth code
	* @return string
    */
    public function getGoogleAuthenticatorCode();
}