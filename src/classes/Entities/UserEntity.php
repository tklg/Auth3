<?php

namespace Auth3\Entities;

class UserEntity implements UserEntityInterface {

	protected $identifier = null;
    protected $email = null;
	protected $hasTwoFactor = false;
	protected $gAuthCode = null;
    protected $verified = false;
    protected $firstname = null;
    protected $familyname = null;
    protected $joindate = null;

	public function __construct($identifier, $email, $firstname, $familyname, $hasTwoFactor, $gAuthCode, $verified, $joindate) {
		$this->identifier = $identifier;
        $this->email = $email;
		$this->hasTwoFactor = $hasTwoFactor;
		$this->gAuthCode = $gAuthCode;
        $this->verified = $verified;
        $this->firstname = $firstname;
        $this->familyname = $familyname;
        $this->joindate = $joindate;
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
     * Return the user's first name.
     *
     * @return string
     */
    public function getFirstname() {
        return $this->firstname;
    }

    /**
     * Return the user's family name.
     *
     * @return string
     */
    public function getFamilyname() {
        return $this->familyname;
    }

    /**
	* Return whether or not the user has 2fa enabled
	* @return boolean
    */
    public function hasTwoFactor() {
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

    /**
    * Return the user's join date
    * @return string
    */
    public function getJoinDate() {
        return $this->joindate;
    }
}