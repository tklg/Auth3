<?php

namespace Auth3\Entities;

use League\OAuth2\Server\Entities\ScopeEntityInterface;

class ScopeEntity implements ScopeEntityInterface {

	protected $identifier;

	public function __construct($identifier) {
		$this->identifier = $identifier;
	}

    /**
     * Get the scope's identifier.
     *
     * @return string
     */
    public function getIdentifier() {
    	return $this->identifier;
    }

    public function jsonSerialize() {
        //echo "SDASDASDASDAd";
        //return $this->identifier;
    	return json_encode([$this->identifier]);
    }
}
