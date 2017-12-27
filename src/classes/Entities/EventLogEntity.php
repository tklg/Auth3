<?php

namespace Auth3\Entities;

class EventLogEntity {

	protected $namespace;
	protected $name;
	protected $detail;
	protected $userId;

	public function __construct($namespace, $name, $detail = '', $userId) {
		$this->namespace = $namespace;
		$this->name = $name;
		$this->detail = $detail;
		$this->userId = $userId;
	}

	public function getNamespace() {
		return $this->namespace;
	}
	public function getName() {
		return $this->name;
	}
	public function getUserId() {
		return $this->userId;
	}
	public function getDetail() {
		return $this->detail;
	}
}