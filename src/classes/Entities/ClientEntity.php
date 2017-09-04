<?php

namespace Auth3\Entities;

use League\OAuth2\Server\Entities\ClientEntityInterface;

class ClientEntity implements ClientEntityInterface {

    protected $identifier;
    protected $name;
    protected $redirectUri;

    public function __construct($identifier, $name, $redirectUri) {
        $this->identifier = $identifier;
        $this->name = $name;
        $this->redirectUri = $redirectUri;
    }

    /**
     * Get the client's identifier.
     *
     * @return string
     */
    public function getIdentifier() {
        return $this->identifier;
    }

    /**
     * Get the client's name.
     *
     * @return string
     */
    public function getName() {
        return $this->name;
    }

    /**
     * Returns the registered redirect URI (as a string).
     *
     * Alternatively return an indexed array of redirect URIs.
     *
     * @return string|string[]
     */
    public function getRedirectUri() {
        return $this->redirectUri;
    }
}
