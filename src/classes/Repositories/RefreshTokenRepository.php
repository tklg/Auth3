<?php

namespace Auth3\Repositories;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use Auth3\Entities\RefreshTokenEntity;
use Auth3\Database\Database;

class RefreshTokenRepository implements RefreshTokenRepositoryInterface {
    /**
     * Creates a new refresh token
     *
     * @return RefreshTokenEntityInterface
     */
    public function getNewRefreshToken() {
        return new RefreshTokenEntity();
    }

    /**
     * Create a new refresh token_name.
     *
     * @param RefreshTokenEntityInterface $refreshTokenEntity
     *
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity) {
        $identifier = hash('sha512', $refreshTokenEntity->getIdentifier());
        $accessToken = hash('sha512', $refreshTokenEntity->getAccessToken()->getIdentifier());
        $expiry = $refreshTokenEntity->getExpiryDateTime()->format('Y-m-d H:i:s');

        $db = Database::getDatabase();

        $stmt = $db->prepare("INSERT INTO auth3_refresh_tokens (refresh_token, access_token, expires) VALUES (:identifier, :accessToken, :expiry)");

        try {
           $stmt->execute(compact('identifier', 'accessToken', 'expiry'));
           // successful insertion, not a duplicate

        } catch (PDOException $e) {
           //if ($e->errorInfo[1] == 1062) {
           if ($e->errorInfo[0] === 23000) {
                // duplicate entry
                throw UniqueTokenIdentifierConstraintViolationException::create();
           } else {
                // an error other than duplicate entry occurred
           }
        }
    }

    /**
     * Revoke the refresh token.
     *
     * @param string $tokenId
     */
    public function revokeRefreshToken($tokenId) {
        $db = Database::getDatabase();
        $tokenId = hash('sha512', $tokenId);

        $stmt = $db->prepare("UPDATE auth3_refresh_tokens SET is_revoked = 1 WHERE refresh_token = :tokenId LIMIT 1");

        return $stmt->execute(compact('tokenId'));
    }

    /**
     * Check if the refresh token has been revoked.
     *
     * @param string $tokenId
     *
     * @return bool Return true if this token has been revoked
     */
    public function isRefreshTokenRevoked($tokenId) {
        $db = Database::getDatabase();
        $tokenId = hash('sha512', $tokenId);

        $stmt = $db->prepare("SELECT is_revoked FROM auth3_refresh_tokens WHERE access_token = :tokenId LIMIT 1");
        $stmt->execute(compact('tokenId'));
        if ($token = $stmt->fetch()) {
            if ($token['is_revoked'] === 1) return true;
            else return false;
        }
        return true;
    }
}
