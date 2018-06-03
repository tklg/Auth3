<?php

namespace Auth3\Repositories;

use \Auth3\Database\Database;

class PasswordRecoveryCodeRepository {
	public function addCodeForUser($userId, $code) {
		$db = Database::getDatabase();

		$sql = "INSERT INTO auth3_password_reset (user_id, code, expires) VALUES (:userId, :code, :expires)";
		
		$expires = new \DateTime();
		$expires = $expires->add(new \DateInterval("PT30M"))->format('Y-m-d H:i:s');

		try {
			$stmt = $db->prepare($sql);
			$stmt->execute(compact('userId', 'code', 'expires'));
			return [
				'message' => 'added recovery codes.'
			];
		} catch (PDOException $e) {
			return null;
		}
	}

	public function removeCodesForUser($userId) {
		$db = Database::getDatabase();
		$stmt = $db->prepare("DELETE FROM auth3_password_reset WHERE user_id = :userId");
		try {
			$stmt->execute(compact('userId'));
			return [
				'message' => 'removed recovery codes.'
			];
		} catch (PDOException $e) {
			return null;
		}
	}

	public function validateCodeForUser($userId, $code) {
		$db = Database::getDatabase();
		$stmt = $db->prepare("SELECT code FROM auth3_password_reset WHERE user_id = :userId AND expires > NOW() LIMIT 1");
		$stmt->execute(compact('userId'));
		if ($codes = $stmt->fetch()) {
			return $codes['code'] == $code;
		}
		return false;
	}
}