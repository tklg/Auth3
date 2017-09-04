<?php

namespace Auth3;

class OAuth2 {
	protected static $server;

	public static function register($key_data) {
		// Init our repositories
		$clientRepository = new \Auth3\Repositories\ClientRepository(); // instance of ClientRepositoryInterface
		$scopeRepository = new \Auth3\Repositories\ScopeRepository(); // instance of ScopeRepositoryInterface
		$accessTokenRepository = new \Auth3\Repositories\AccessTokenRepository(); // instance of AccessTokenRepositoryInterface
		$userRepository = new \Auth3\Repositories\UserRepository(); // instance of UserRepositoryInterface
		$refreshTokenRepository = new \Auth3\Repositories\RefreshTokenRepository(); // instance of RefreshTokenRepositoryInterface
		$authCodeRepository = new \Auth3\Repositories\AuthCodeRepository(); // instance of AuthCodeRepositoryInterface

		// Path to public and private keys
		$privateKey = new \League\OAuth2\Server\CryptKey($key_data['privateKey'], null, false);
		if (isset($key_data['privateKeyPassPhrase'])) {
			$privateKey = new \League\OAuth2\Server\CryptKey($key_data['privateKey'], $key_data['privateKeyPassPhrase']); // if private key has a pass phrase
		}
		$encryptionKey = $key_data['encryptionKey']; // generate using base64_encode(random_bytes(32))

		// Setup the authorization server
		$server = new \League\OAuth2\Server\AuthorizationServer(
		    $clientRepository,
		    $accessTokenRepository,
		    $scopeRepository,
		    $privateKey,
		    $encryptionKey
		);

		$grant = new \Auth3\Grant\TwoFactorPasswordGrant(
		     $userRepository,
		     $refreshTokenRepository
		);
		$grant->setRefreshTokenTTL(new \DateInterval('P1M')); // refresh tokens will expire after 1 month
		$server->enableGrantType(
		    $grant,
		    new \DateInterval('PT1H') // access tokens will expire after 1 hour
		);

		$grant = new \League\OAuth2\Server\Grant\AuthCodeGrant(
		     $authCodeRepository,
		     $refreshTokenRepository,
		     new \DateInterval('PT10M') // authorization codes will expire after 10 minutes
		 );
		$grant->setRefreshTokenTTL(new \DateInterval('P1M')); // refresh tokens will expire after 1 month
		$server->enableGrantType(
		    $grant,
		    new \DateInterval('PT1H') // access tokens will expire after 1 hour
		);

		$grant = new \League\OAuth2\Server\Grant\RefreshTokenGrant($refreshTokenRepository);
		$grant->setRefreshTokenTTL(new \DateInterval('P1M')); // new refresh tokens will expire after 1 month
		$server->enableGrantType(
		    $grant,
		    new \DateInterval('PT1H') // new access tokens will expire after an hour
		);

		self::$server = $server;

		return self::$server;
	}

	public static function getServer() {
		return self::$server;
	}
}