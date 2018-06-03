<?php

namespace Auth3\Util;

use DeviceDetector\DeviceDetector;

class UserData {
	private static function getIP() {
		$ip = $_SERVER['REMOTE_ADDR'];
		if ($ip == '::1') return '127.0.0.1';
		else if (!$ip) return '';
		else return $ip;
	}
	private static function getDeviceInfo() {
		if (!isset($_SERVER['HTTP_USER_AGENT'])) return null;
		$dd = new DeviceDetector($_SERVER['HTTP_USER_AGENT']);
		$dd->skipBotDetection();
		$dd->parse();
		$info = [
			'client' => $dd->getClient(), // holds information about browser, feed reader, media player, ...
			'os' => $dd->getOs(),
			'device' => $dd->getDevice(),
			'brand' => $dd->getBrandName(),
			'model' => $dd->getModel()
		];
		return $info;
	}
	private static function getLocation($ip = NULL, $purpose = "country", $deep_detect = TRUE) {
		// http://stackoverflow.com/questions/12553160/getting-visitors-country-from-their-ip
	    $output = NULL;
	    if (filter_var($ip, FILTER_VALIDATE_IP) === FALSE) {
	        $ip = $_SERVER["REMOTE_ADDR"];
	        if ($deep_detect) {
	            if (filter_var(@$_SERVER['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP))
	                $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
	            if (filter_var(@$_SERVER['HTTP_CLIENT_IP'], FILTER_VALIDATE_IP))
	                $ip = $_SERVER['HTTP_CLIENT_IP'];
	        }
	    }
	    $purpose    = str_replace(array("name", "\n", "\t", " ", "-", "_"), NULL, strtolower(trim($purpose)));
	    $support    = array("country", "countrycode", "state", "region", "city", "location", "address");
	    $continents = array(
	        "AF" => "Africa",
	        "AN" => "Antarctica",
	        "AS" => "Asia",
	        "EU" => "Europe",
	        "OC" => "Australia (Oceania)",
	        "NA" => "North America",
	        "SA" => "South America"
	    );
	    if (filter_var($ip, FILTER_VALIDATE_IP) && in_array($purpose, $support)) {
	    	if ($ip == 'localhost' || $ip == '::1' || $ip == '127.0.0.1') {
	    		return 'localhost';
	    	} else {
	        	$ipdat = @json_decode(file_get_contents("http://www.geoplugin.net/json.gp?ip=" . $ip));
	    	}
	        if (@strlen(trim($ipdat->geoplugin_countryCode)) == 2) {
	            switch ($purpose) {
	                case "location":
	                    $output = array(
	                        "city"           => @$ipdat->geoplugin_city,
	                        "state"          => @$ipdat->geoplugin_regionName,
	                        "country"        => @$ipdat->geoplugin_countryName,
	                        "country_code"   => @$ipdat->geoplugin_countryCode,
	                        "continent"      => @$continents[strtoupper($ipdat->geoplugin_continentCode)],
	                        "continent_code" => @$ipdat->geoplugin_continentCode
	                    );
	                    break;
	                case "address":
	                    $address = array($ipdat->geoplugin_countryName);
	                    if (@strlen($ipdat->geoplugin_regionName) >= 1)
	                        $address[] = $ipdat->geoplugin_regionName;
	                    if (@strlen($ipdat->geoplugin_city) >= 1)
	                        $address[] = $ipdat->geoplugin_city;
	                    $output = implode(", ", array_reverse($address));
	                    break;
	                case "country":
	                    $output = @$ipdat->geoplugin_countryName;
	                    break;
	            }
	        }
	    }
	    return $output;
	}
	public static function getUserData() {
		$deviceInfo = UserData::getDeviceInfo();
		if ($deviceInfo) {
			$device = $deviceInfo['device'] == 1 ? $deviceInfo['brand'].' '.$deviceInfo['model'] : '';
		} else $device = '';
		return [
			'ip' => UserData::getIP(),
			'os' => $deviceInfo ? ($deviceInfo['os']['name'].' '.$deviceInfo['os']['version']) : '',
			'country' => UserData::getLocation(UserData::getIP(), 'country'),
			'browser' => $deviceInfo ? ($deviceInfo['client']['name'].' '.$deviceInfo['client']['version']) : '',
			'device' => $device
		];
	}
}