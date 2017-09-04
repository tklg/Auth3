<?php

namespace Auth3\Database;

class Database {

	// the pdo instance
	protected static $pdo;
	// db login
	protected static $db_info;

	/**
	* Register a PDO database instance
	* @param Array 	$db_info
	*/
	public static function register($db_info) {
		if (!isset(self::$db_info)) self::$db_info = $db_info;
		else if (!isset($db_info)) $db_info = self::$db_info;
		$newpdo = new \PDO("mysql:host=" . $db_info['host'] . ";dbname=" . $db_info['dbname'],
        $db_info['user'], $db_info['pass']);
	    $newpdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
	    $newpdo->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC);
	    self::$pdo = $newpdo;
	    return self::$pdo;
	}

	public static function getDatabase() {
		return self::$pdo;
	}
}