<?php

namespace Auth3\Repositories;

use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use Auth3\Entities\UserEntity;
use Auth3\Database\Database;

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
            $password_hash = $user['password'];
            $gAuthCode = $user['twofactor_enabled'];
            $hasTwoFactor = $gAuthCode != '';

    		if (password_verify($password, $password_hash)) {
    			return new UserEntity($id, $username, $hasTwoFactor, $gAuthCode);
    		}

    	}
    	return null;
    }

}