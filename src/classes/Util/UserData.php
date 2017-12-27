<?php

namespace Auth3\Util;

class UserData {
	private static function getIP() {
		$ip = $_SERVER['REMOTE_ADDR'];
		if ($ip == '::1') return '127.0.0.1';
		else return $ip;
	}
	private static function getOS() { 
	    $user_agent = $_SERVER['HTTP_USER_AGENT'];
	    $os_platform = "Unknown OS";
	    $os_array = array('/windows nt 10/i'=>'Windows 10', '/windows nt 6.3/i'=>'Windows 8.1', '/windows nt 6.2/i'=>'Windows 8', '/windows nt 6.1/i'=>'Windows 7', '/windows nt 6.0/i'=>'Windows Vista', '/windows nt 5.2/i'=>'Windows Server 2003', '/windows nt 5.1/i'=>'Windows XP', '/windows xp/i'=>'Windows XP', '/windows nt 5.0/i'=>'Windows 2000', '/windows me/i'=>'Windows ME', '/win98/i'=>'Windows 98', '/win95/i'=>'Windows 95', '/win16/i'=>'Windows 3.11', '/macintosh|mac os x/i'=>'Mac OS X', '/mac_powerpc/i'=>'Mac OS 9', '/linux/i'=>'Linux', '/ubuntu/i'=>'Ubuntu', '/iphone/i'=>'iPhone', '/ipod/i'=>'iPod', '/ipad/i'=>'iPad', '/android/i'=>'Android', '/blackberry/i'=>'BlackBerry', '/webos/i'=>'Mobile'); foreach ($os_array as $regex => $value) {
	        if (preg_match($regex, $user_agent)) {
	            $os_platform = $value;
	        }
	    }   
	    return $os_platform;
	}
	private static function getBrowser() {
		$user_agent = $_SERVER['HTTP_USER_AGENT'];
	    $browser  = "Unknown";
	    $browser_array = array('/msie/i' => 'IE', '/firefox/i' => 'Firefox', '/safari/i' => 'Safari', '/chrome/i' => 'Chrome', '/edge/i' => 'Edge', '/opera/i' => 'Opera', '/netscape/i' => 'Netscape', '/maxthon/i' => 'Maxthon', '/konqueror/i' => 'Konqueror', '/mobile/i' => 'Mobile Browser'); foreach ($browser_array as $regex => $value) {
	        if (preg_match($regex, $user_agent)) {
	            $browser = $value;
	        }
	    }
	    return $browser;
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
		return [
			'ip' => UserData::getIP(),
			'os' => UserData::getOS(),
			'country' => UserData::getLocation(UserData::getIP(), 'country'),
			'browser' => UserData::getBrowser()
		];
	}
}