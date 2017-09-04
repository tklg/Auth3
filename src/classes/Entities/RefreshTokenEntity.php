<?php

namespace Auth3\Entities;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;

class RefreshTokenEntity implements RefreshTokenEntityInterface {

    protected $identifier;
    protected $expiryDateTime;
    protected $accessToken;

    public function __construct() {
        
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
     * Set the access token that the refresh token was associated with.
     *
     * @param AccessTokenEntityInterface $accessToken
     */
    public function setAccessToken(AccessTokenEntityInterface $accessToken) {
        $this->accessToken = $accessToken;
    }

    /**
     * Get the access token that the refresh token was originally associated with.
     *
     * @return AccessTokenEntityInterface
     */
    public function getAccessToken() {
        return $this->accessToken;
    }
}
