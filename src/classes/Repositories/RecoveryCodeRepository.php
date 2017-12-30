<?php

namespace Auth3\Repositories;

use \Auth3\Database\Database;

class RecoveryCodeRepository {
	public function addCodesForUser($userId, array $codes) {
		$db = Database::getDatabase();

		$sql = "INSERT INTO auth3_recovery_codes (user_id, code) VALUES ";
		$temp = "(?, ?)";

		$data = [];

		for ($i = 0; $i < sizeof($codes); $i++) {
			if ($i > 0) $sql .= ", ";
			$sql .= $temp;
			$v = [$userId, $codes[$i]];
			$data = array_merge($data, $v);
		}

		try {
			$stmt = $db->prepare($sql);
			$stmt->execute($data);
			return [
				'message' => 'added recovery codes.'
			];
		} catch (PDOException $e) {
			return null;
		}
	}

	public function removeCodesForUser($userId) {
		$db = Database::getDatabase();
		$stmt = $db->prepare("DELETE FROM auth3_recovery_codes WHERE user_id = :userId");
		try {
			$stmt->execute(compact('userId'));
			return [
				'message' => 'removed recovery codes.'
			];
		} catch (PDOException $e) {
			return null;
		}
	}

	public function getCodesForUser($userId) {
		$db = Database::getDatabase();
		$stmt = $db->prepare("SELECT code FROM auth3_recovery_codes WHERE user_id = :userId");
		$stmt->execute(compact('userId'));
		if ($codes = $stmt->fetchAll()) {
			return $codes;
		}
		return null;
	}
}