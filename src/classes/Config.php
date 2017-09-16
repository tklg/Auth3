<?php

namespace Auth3;

class Config {
	public static function getConfig() {
		return [
			'displayErrorDetails' => true,
			'addContentLengthHeader' => false,
			'db' => [
				'host' => 'localhost',
				'user' => 'auth3',
				'pass' => 'auth3',
				'dbname' => 'auth3'
			]
		];
	}
}