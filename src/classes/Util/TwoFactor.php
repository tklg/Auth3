<?php

namespace Auth3\Util;

class TwoFactor {
	/**
     * Generate the URL for the Google Charts API to make the QR code
     * To use in an image tag:
     *
     * '<img src="data:image/png;base64,'.base64_encode($data).'"/>
     *
     * @param string $holder Account identifier (email, username, etc)
     * @param string $name Name of the application
     * @param integer $size Height x Width in pixels of the resulting image
     */
    public static function generateQrImage($holder, $name, $initKey, $size = 30) {
      $data = 'otpauth://totp/'.$name.' ('.$holder.')?secret='.$initKey;

      $renderer = new \BaconQrCode\Renderer\Image\Png();
      $renderer->setMargin(0)
        ->setHeight($size)
        ->setWidth($size);
      $writer = new \BaconQrCode\Writer($renderer);

      return $writer->writeString($data);
    }

    public static function generateToken($len = 40) {
        if (function_exists('mcrypt_create_iv')) {
            $randomData = mcrypt_create_iv(100, MCRYPT_DEV_URANDOM);
        } else if (function_exists('openssl_random_pseudo_bytes')) {
            $randomData = openssl_random_pseudo_bytes(100);
        } else if (@file_exists('/dev/urandom')) { // Get 100 bytes of random data
            $randomData = file_get_contents('/dev/urandom', false, null, 0, 100) . uniqid(mt_rand(), true);
        } else {
            $randomData = mt_rand() . mt_rand() . mt_rand() . mt_rand() . microtime(true) . uniqid(mt_rand(), true);
        }
        return substr(hash('sha512', $randomData), 0, $len);
    }

    public static function generateRecoveryCodes($num = 10) {
        $codes = [];
        for ($i = 0; $i < $num; $i++) {
          $code = TwoFactor::generateToken(10);
          //$codes[] = preg_replace('/(.{5})(.{5})/', "$1-$2", $code);
          $codes[] = $code;
          ///$todb[] = "('".$email."','".$codes[$i]."')";
        }
        return $codes;
        //$q = "INSERT into gauth_recovery_codes (user_id, code) values ".implode(',', $todb);
    }
}