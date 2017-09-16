<?php

namespace Auth3\Entities;

use \League\OAuth2\Server\Entities\AuthCodeEntityInterface;

class AuthCodeEntity implements AuthCodeEntityInterface {

    protected $redirectUri;

    /**
     * @return string
     */
    public function getRedirectUri() {
    	return $this->redirectUri;
    }

    /**
     * @param string $uri
     */
    public function setRedirectUri($uri) {
    	$this->redirectUri = $uri;
    }
}
