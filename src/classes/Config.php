<?php

namespace Auth3;

class Config {
	public static function getConfig() {
		return [
			'displayErrorDetails' => true,
			'addContentLengthHeader' => false,
			'privateKey' => 'J:\BitNami\xampp\htdocs\auth3\keys\private.key',
			'publicKey' => 'J:\BitNami\xampp\htdocs\auth3\keys\public.key',
			'encryptionKey' => '6kwILTHs88Z2dCWgoyc3gx5d8Dl7QGPBjrVfhixzsSE=',
			'db' => [
				'host' => 'localhost',
				'user' => 'auth3',
				'pass' => 'auth3',
				'dbname' => 'auth3'
			],
			'captcha' => '6LdxLCcUAAAAAEZqZx8XKjp__eNnlv537mJ7D28t',
			'email' => [
				'smtp_hostname' => 'smtp.mailgun.org',
				'smtp_login' => 'postmaster@sandbox3e7a636467bd4ec9ad7e0cd6bd37237b.mailgun.org',
				'api_base_url' => 'https://api.mailgun.net/v3/sandbox3e7a636467bd4ec9ad7e0cd6bd37237b.mailgun.org',
				'default_password' => '6d0bea2bf013ee7500de23d68c0cd15e',
				'api_key' => 'key-edc5fad8aa830aef98aeadd8dfe3dc65'
			]
		];
	}
}