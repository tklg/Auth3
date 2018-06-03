<?php

namespace Auth3\Repositories;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use Auth3\Entities\AuthCodeEntity;
use Auth3\Database\Database;

/**
 * Auth code storage interface.
 */
class AuthCodeRepository implements AuthCodeRepositoryInterface {
    /**
     * Creates a new AuthCode
     *
     * @return AuthCodeEntityInterface
     */
    public function getNewAuthCode() {
        return new AuthCodeEntity('');
    }

    /**
     * Persists a new auth code to permanent storage.
     *
     * @param AuthCodeEntityInterface $authCodeEntity
     *
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity) {
        $db = Database::getDatabase();

        $scopes = $authCodeEntity->getScopes();
        if ($scopes[0] instanceof Auth3\Entities\ScopeEntity) {
            $scopeStrings = [];
            for ($i = 0; $i < count($scopes); $i++) {
                $scopeStrings[] = $scopes[$i]->getIdentifier();
            }
            $scopes = join(',', $scopeStrings);
        } else {
            $scopes = join(',', $scopes);
        }

        $clientId = $authCodeEntity->getClient()->getIdentifier();
        $userId = $authCodeEntity->getUserIdentifier();
        //$authCode = hash('sha512', $authCodeEntity->getIdentifier());
        $authCode = $authCodeEntity->getIdentifier();
        $expires = $authCodeEntity->getExpiryDateTime()->format('Y-m-d H:i:s');

        $stmt = $db->prepare("INSERT INTO auth3_authorization_codes (user_id, client_id, authorization_code, expires, scopes) VALUES (:userId, :clientId, :authCode, :expires, :scopes)");

        try {
           $stmt->execute(compact('userId', 'clientId', 'authCode', 'expires', 'scopes'));
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
     * Revoke an auth code.
     *
     * @param string $codeId
     */
    public function revokeAuthCode($codeId) {
        $db = Database::getDatabase();
        //$authCode = hash('sha512', $codeId);
        $authCode = $codeId;
        $stmt = $db->prepare("UPDATE auth3_authorization_codes SET is_revoked = 1 WHERE authorization_code = :authCode LIMIT 1");
        return $stmt->execute(compact('authCode'));
    }

    /**
     * Check if the auth code has been revoked.
     *
     * @param string $codeId
     *
     * @return bool Return true if this code has been revoked
     */
    public function isAuthCodeRevoked($codeId) {
        $db = Database::getDatabase();
        //$authCode = hash('sha512', $codeId);
        $authCode = $codeId;

        $stmt = $db->prepare("SELECT is_revoked FROM auth3_authorization_codes WHERE authorization_code = :authCode LIMIT 1");
        $stmt->execute(compact('authCode'));
        if ($token = $stmt->fetch()) {
            if ($token['is_revoked'] === 1) return true;
            else return false;
        }
        return true;
    }
}
