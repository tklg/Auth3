<?php

namespace Auth3\Repositories;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use Auth3\Entities\AccessTokenEntity;
use Auth3\Database\Database;

class AccessTokenRepository implements AccessTokenRepositoryInterface {
    /**
     * Create a new access token
     *
     * @param ClientEntityInterface  $clientEntity
     * @param ScopeEntityInterface[] $scopes
     * @param mixed                  $userIdentifier
     *
     * @return AccessTokenEntityInterface
     */
    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null) {
        //$token = bin2hex(openssl_random_pseudo_bytes(24));
        $tok = new AccessTokenEntity('');
        $tok->setClient($clientEntity);
        $tok->setUserIdentifier($userIdentifier);
        foreach ($scopes as $scope) {
            //print_r($scope);
            $tok->addScope($scope);
        }
        //print_r(json_encode($tok->getScopes()));
        /*print_r(json_encode([
            'scopes' => $tok->getScopes()
        ]));*/
        return $tok;
    }

    /**
     * Persists a new access token to permanent storage.
     *
     * @param AccessTokenEntityInterface $accessTokenEntity
     *
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity) {
        $scopes = $accessTokenEntity->getScopes();
        /*$scopeStrings = [];
        for ($i = 0; $i < count($scopes); $i++) {
            $scopeStrings[] = $scopes[$i]->getIdentifier();
        }
        $scopes = join(',', $scopeStrings);*/
        $scopes = join(',', $scopes);
        $token = hash('sha512', $accessTokenEntity->getIdentifier());
        $userIdentifier = $accessTokenEntity->getUserIdentifier();
        $clientIdentifier = $accessTokenEntity->getClient()->getIdentifier();
        $expiryDateTime = $accessTokenEntity->getExpiryDateTime()->format('Y-m-d H:i:s');
        $userData = \Auth3\Util\UserData::getUserData();
        $ip = $userData['ip'];
        $os = $userData['os'];
        $browser = $userData['browser'];
        $country = $userData['country'];

        $db = Database::getDatabase();

        $stmt = $db->prepare("INSERT INTO auth3_access_tokens (user_id, client_id, access_token, expires, scopes, ip_address, browser, operating_system, country) VALUES (:userIdentifier, :clientIdentifier, :token, :expiryDateTime, :scopes, :ip, :browser, :os, :country)");

        try {
           $stmt->execute(compact('userIdentifier', 'clientIdentifier', 'token', 'expiryDateTime', 'scopes', 'ip', 'browser', 'os', 'country'));
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
     * Revoke an access token.
     *
     * @param string $tokenId
     */
    public function revokeAccessToken($tokenId) {
        $db = Database::getDatabase();
        $tokenId = hash('sha512', $tokenId);

        $stmt = $db->prepare("UPDATE auth3_access_tokens SET is_revoked = 1 WHERE access_token = :tokenId LIMIT 1");

        return $stmt->execute(compact('tokenId'));
    }

    /**
     * Revoke an access token by db id.
     *
     * @param string $tokenId
     */
    public function revokeAccessTokenById($tokenId) {
        $db = Database::getDatabase();

        $stmt = $db->prepare("UPDATE auth3_access_tokens SET is_revoked = 1 WHERE id = :tokenId LIMIT 1");

        return $stmt->execute(compact('tokenId'));
    }

    /**
     * Check if the access token has been revoked.
     *
     * @param string $tokenId
     *
     * @return bool Return true if this token has been revoked
     */
    public function isAccessTokenRevoked($tokenId) {
        $db = Database::getDatabase();
        $tokenId = hash('sha512', $tokenId);

        $stmt = $db->prepare("SELECT is_revoked FROM auth3_access_tokens WHERE access_token = :tokenId LIMIT 1");
        $stmt->execute(compact('tokenId'));
        if ($token = $stmt->fetch()) {
            if ($token['is_revoked'] == 1) return true;
            else return false;
        }
        return true;
    }

    /**
    *   get a list of access tokens owned by a user
    */
    public function getAccessTokensByUserId($userId, $currentTokenId = '') {
        $db = Database::getDatabase();

        $stmt = $db->prepare("SELECT at.id, at.client_id, cl.client_display, at.ip_address as ip, at.browser, at.operating_system as os, at.country, at.scopes, at.created, at.expires ".
                             "FROM auth3_access_tokens at, auth3_clients cl ".
                             "WHERE at.client_id = cl.id AND at.is_revoked = 0 AND at.user_id = :userId AND at.expires > NOW() ".
                             "ORDER BY at.expires ASC");
        $stmt->execute(compact('userId'));

        if ($tokens = $stmt->fetchAll()) {
           /* for ($i = 0; $i < sizeof($tokens); $i++) {
                if ($tokens[$i]['access_token'] == $currentTokenId) $tokens[$i]['current'] = true;
                else $tokens[$i]['current'] = false;
                unset($tokens[$i]['access_token']);
                //$tokens[$i]['com'] = $currentTokenId;
            }*/
            return $tokens;
        }
        return null;
    }
}
