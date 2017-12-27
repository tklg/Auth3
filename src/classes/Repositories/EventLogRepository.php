<?php

namespace Auth3\Repositories;

use Auth3\Database\Database;
use Auth3\Entities\EventLogEntity;

class EventLogRepository {
	/**
	* 	add an event to the database
	*/
	public function addEvent(EventLogEntity $event) {
		$db = Database::getDatabase();

		$namespace = $event->getNamespace();
		$name = $event->getName();
		$userId = $event->getUserId();
		$detail = $event->getDetail();

		$stmt = $db->prepare("INSERT INTO auth3_history (namespace, action, detail, user_id) VALUES (:namespace, :name, :detail, :userId)");
		$stmt->execute(compact('namespace', 'name', 'detail', 'userId'));
	}

	/**
	* get a list of all events for a user id
	*/
	public function getEventsByUserId($userId) {
		$db = Database::getDatabase();

        $stmt = $db->prepare("SELECT e.namespace, e.action, e.detail, e.time FROM auth3_history e WHERE e.user_id = :userId LIMIT 50");
        $stmt->execute(compact('userId'));

        if ($tokens = $stmt->fetchAll()) {
            return $tokens;
        }
        return [];
	}
}