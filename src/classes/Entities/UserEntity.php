<?php

namespace Auth3\Entities;

class UserEntity implements UserEntityInterface {

	protected $identifier = null;
    protected $email = null;
	protected $hasTwoFactor = false;
	protected $gAuthCode = null;
    protected $verified = false;

	public function __construct($identifier, $email, $hasTwoFactor, $gAuthCode, $verified) {
		$this->identifier = $identifier;
        $this->email = $email;
		$this->hasTwoFactor = $hasTwoFactor;
		$this->gAuthCode = $gAuthCode;
        $this->verified = $verified;
	}

    /**
     * Return the user's identifier.
     *
     * @return mixed
     */
    public function getIdentifier() {
    	return $this->identifier;
    }

    /**
     * Return the user's email.
     *
     * @return string
     */
    public function getEmail() {
        return $this->email;
    }

    /**
	* Return whether or not the user has 2fa enabled
	* @return boolean
    */
    public function hasTwoFactorEnabled() {
    	return $this->hasTwoFactor;
    }

    /**
	* Return the user's unique gauth code
	* @return string
    */
    public function getGoogleAuthenticatorCode() {
    	return $this->gAuthCode;
    }

    /**
    * Return the user's email verification status
    * @return string
    */
    public function getEmailVerification() {
        return $this->verified;
    }
}