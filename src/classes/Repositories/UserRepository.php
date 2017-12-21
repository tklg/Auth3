<?php

namespace Auth3\Repositories;

use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use Auth3\Entities\UserEntity;
use Auth3\Database\Database;
use Auth3\Captcha\Recaptcha;

class UserRepository implements UserRepositoryInterface {

	/**
     * Get a user entity.
     *
     * @param string                $username
     * @param string                $password
     * @param string                $grantType    The grant type used
     * @param ClientEntityInterface $clientEntity
     *
     * @return UserEntityInterface
     */
    public function getUserEntityByUserCredentials(
        $username,
        $password,
        $grantType,
        ClientEntityInterface $clientEntity
    ) {
    	// check username, password against database
    	// check granttype against client to see if user is permitted to use grant type with the client

    	// if valid, return instance of Auth3\UserEntity (UserEntityInterface)
    	// else return null

        $db = Database::getDatabase(); // pdo instance

        $stmt = $db->prepare("SELECT * FROM auth3_users WHERE email = :username LIMIT 1");
        $stmt->execute(compact('username'));

        if ($user = $stmt->fetch()) {

            $id = $user['id'];
            $firstname = $user['first_name'];
            $familyname = $user['family_name'];
            $password_hash = $user['password'];
            $gAuthCode = $user['twofactor'];
            $hasTwoFactor = $gAuthCode != '';
            $verified = $user['verification_status'] == 'verified';

    		if (password_verify($password, $password_hash)) {
    			return new UserEntity($id, $username, $firstname, $familyname, $hasTwoFactor, $gAuthCode, $verified);
    		}

    	}
    	return null;
    }

    /**
    * @return UserEntityInterface
     */
    public function getUserEntityByIdentifier($identifier) {
        $db = Database::getDatabase();

        $stmt = $db->prepare("SELECT * FROM auth3_users WHERE id = :identifier LIMIT 1");
        $stmt->execute(compact('identifier'));

        if ($user = $stmt->fetch()) {

            $username = $user['email'];
            $firstname = $user['first_name'];
            $familyname = $user['family_name'];
            $gAuthCode = $user['twofactor'];
            $hasTwoFactor = $gAuthCode != '';
            $verified = $user['verification_status'] == 'verified';
            
            return new UserEntity($identifier, $username, $firstname, $familyname, $hasTwoFactor, $gAuthCode, $verified);
        }
        return null;
    }

    /**
    * @return UserEntityInterface
    */
    public function getUserEntityByEmail($email) {
        $db = Database::getDatabase();

        $stmt = $db->prepare("SELECT * FROM auth3_users WHERE email = :email LIMIT 1");
        $stmt->execute(compact('email'));

        if ($user = $stmt->fetch()) {

            $identifier = $user['id'];
            $username = $user['email'];
            $firstname = $user['first_name'];
            $familyname = $user['family_name'];
            $gAuthCode = $user['twofactor'];
            $hasTwoFactor = $gAuthCode != '';
            $verified = $user['verification_status'] == 'verified';
            
            return new UserEntity($identifier, $username, $firstname, $familyname, $hasTwoFactor, $gAuthCode, $verified);
        }
        return null;
    }
    /**
    * @return Array
    */
    public function createUser($email, $password, $recaptcha) {
        if ($this->getUserEntityByEmail($email) != null) { // user already exists, do not create
            return [
                'error' => 'An account with that email already exists.'
            ];
        }
        if (!Recaptcha::verify($recaptcha, $_SERVER['REMOTE_ADDR'])) { // invalid captcha, fail
            return [
                'error' => 'Recaptcha was invalid. Please try again.'
            ];
        }

        // if the user manages to submit 2 different passwords, that's on them for bypassing clientside protections
        $db = Database::getDatabase();
        $hashedpassword = password_hash($password, PASSWORD_DEFAULT);
        if (function_exists('random_bytes')) {
            $bytes = bin2hex(random_bytes(20));
        } else {
            $bytes = bin2hex(openssl_random_pseudo_bytes(20));
        }
        $stmt = $db->prepare("INSERT INTO auth3_users (email, password, verification_status) VALUES (:email, :hashedpassword, :bytes)");
        $stmt->execute(compact('email', 'hashedpassword', 'bytes'));

        return [
            'error' => 'success',
            'user' => $this->getUserEntityByEmail($email)
        ];
    }

}