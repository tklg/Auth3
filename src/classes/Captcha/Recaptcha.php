<?php

namespace Auth3\Captcha;

class Recaptcha {

	protected static $RECAPTCHA_API_URL = 'https://www.google.com/recaptcha/api/siteverify';

	public static function verify($response, $remoteip) {
		$data = [
			'secret' => RecaptchaKey::getKey(),
			'response' => $response,
   			'remoteip' => $remoteip
   		];
   		$url = self::$RECAPTCHA_API_URL . "?" . http_build_query($data);
   		if (false && function_exists('curl_version')) {
			$curl = curl_init($url);
			//curl_setopt($curl, CURLOPT_URL, self::$RECAPTCHA_API_URL);
			//curl_setopt($curl, CURLOPT_POST, true);
			curl_setopt($curl, CURLOPT_HEADER, false);
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
			/*curl_setopt($curl, CURLOPT_HTTPHEADER, [
				'Content-Type: application/x-www-form-urlencoded; charset=utf-8', 
	   			'Content-Length: ' . strlen($data)
	   		]);
	   		curl_setopt($curl, CURLOPT_POSTFIELDS, $data);*/
	   		$out = curl_exec($curl);
			curl_close($curl);
   		} else {
   			$out = file_get_contents($url);
   		}
		if (empty($out) || is_null($out)) {
			return false;
		}
		$result = json_decode($out);
		return $result->success;
	}
}