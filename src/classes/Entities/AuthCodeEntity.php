<?php

namespace Auth3\Entities;

use \League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;

class AuthCodeEntity implements AuthCodeEntityInterface {

    protected $redirectUri;
    protected $identifier;
    protected $userIdentifier;
    /**
    * @var DateTime
    */
    protected $expiryDateTime;
    /**
    * @var ClientEntityInterface
    */
    protected $client;
    /**
    * @var ScopeEntityInterface[]
    */
    protected $scopes = [];

    public function __construct($identifier) {
        $this->identifier = $identifier;
    }

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
    /**
     * Get the token's identifier.
     *
     * @return string
     */
    public function getIdentifier() {
        return $this->identifier;
    }

    /**
     * Set the token's identifier.
     *
     * @param $identifier
     */
    public function setIdentifier($identifier) {
        $this->identifier = $identifier;
    }

    /**
     * Get the token's expiry date time.
     *
     * @return \DateTime
     */
    public function getExpiryDateTime() {
        return $this->expiryDateTime;
    }

    /**
     * Set the date time when the token expires.
     *
     * @param \DateTime $dateTime
     */
    public function setExpiryDateTime(\DateTime $dateTime) {
        $this->expiryDateTime = $dateTime;
    }

    /**
     * Set the identifier of the user associated with the token.
     *
     * @param string|int $identifier The identifier of the user
     */
    public function setUserIdentifier($identifier) {
        $this->userIdentifier = $identifier;
    }

    /**
     * Get the token user's identifier.
     *
     * @return string|int
     */
    public function getUserIdentifier() {
        return $this->userIdentifier;
    }

    /**
     * Get the client that the token was issued to.
     *
     * @return ClientEntityInterface
     */
    public function getClient() {
        return $this->client;
    }

    /**
     * Set the client that the token was issued to.
     *
     * @param ClientEntityInterface $client
     */
    public function setClient(ClientEntityInterface $client) {
        $this->client = $client;
    }

    /**
     * Associate a scope with the token.
     *
     * @param ScopeEntityInterface $scope
     */
    public function addScope(ScopeEntityInterface $scope) {
        $needsToAdd = true;
        foreach ($this->scopes as $s) {
            if ($s->getIdentifier() === $scope->getIdentifier()) $needsToAdd = false;
        }
        if ($needsToAdd) {
            array_push($this->scopes, $scope);
        }
    }

    /**
     * Return an array of scopes associated with the token.
     *
     * @return ScopeEntityInterface[]
     */
    public function getScopes() {
        //return $this->scopes;
        $scopes = [];
        foreach ($this->scopes as $scope) $scopes[] = $scope->getIdentifier();
        return $scopes;
    }
}
