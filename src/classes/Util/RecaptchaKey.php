<?php

namespace Auth3\Util;

class RecaptchaKey {

	// change this to get the key from a keystore or somewhere better
	public static function getKey() {
		//return '6LdxLCcUAAAAAEZqZx8XKjp__eNnlv537mJ7D28t';
		return \Auth3\Config::getConfig()['captcha'];
	}
}