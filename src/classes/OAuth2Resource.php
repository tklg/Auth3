<?php

namespace Auth3;

class OAuth2Resource {
	protected static $server;

	public static function register($key_data) {
		$accessTokenRepository = new \Auth3\Repositories\AccessTokenRepository(); // instance of AccessTokenRepositoryInterface

		// Path to public and private keys
		$publicKey = new \League\OAuth2\Server\CryptKey($key_data['publicKey'], null, false);
		
		$server = new \League\OAuth2\Server\ResourceServer(
		    $accessTokenRepository,
		    $publicKey
		);

		self::$server = $server;

		return self::$server;
	}

	public static function getServer() {
		return self::$server;
	}
}