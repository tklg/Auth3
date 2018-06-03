<?php

namespace Auth3\Repositories;

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Auth3\Entities\ClientEntity;
use Auth3\Database\Database;

class ClientRepository implements ClientRepositoryInterface {
    /**
     * Get a client.
     *
     * @param string      $clientIdentifier   The client's identifier
     * @param string      $grantType          The grant type used
     * @param null|string $clientSecret       The client's secret (if sent)
     * @param bool        $mustValidateSecret If true the client must attempt to validate the secret if the client
     *                                        is confidential
     *
     * @return ClientEntityInterface
     */
    public function getClientEntity($clientIdentifier, $grantType, $clientSecret = null, $mustValidateSecret = true) {
        $db = Database::getDatabase(); // pdo instance

        $stmt = $db->prepare("SELECT * FROM auth3_clients WHERE client_name = :clientIdentifier LIMIT 1");
        $stmt->execute(compact('clientIdentifier'));

        if ($client = $stmt->fetch()) {

            $availableGrantTypes = $client['grant_types'];
            $secret = $client['client_secret'];
            $redirectUri = $client['redirect_uri'];
            $clientDisplayName = $client['client_display'];
            $clientID = $client['id'];
            if ($mustValidateSecret && $secret !== $clientSecret) {
                return null;
            }
            if ($this->isGrantTypeIncluded($grantType, $availableGrantTypes)) {
                 return new ClientEntity($clientID, $clientDisplayName, $redirectUri);
            }
        }
        return null;
    }

    public function getClientEntityById($clientId) {
        $db = Database::getDatabase();
        $stmt = $db->prepare("SELECT * from auth3_clients WHERE id = :clientId LIMIT 1");
        $stmt->execute(compact('clientId'));

        if ($client = $stmt->fetch()) {
            $availableGrantTypes = $client['grant_types'];
            $secret = $client['client_secret'];
            $redirectUri = $client['redirect_uri'];
            $clientDisplayName = $client['client_display'];
            $clientID = $client['id'];
            return new ClientEntity($clientID, $clientDisplayName, $redirectUri);
        }
        return null;
    }

    public function getClientEntityByName($clientName) {
        $db = Database::getDatabase();
        $stmt = $db->prepare("SELECT * from auth3_clients WHERE client_name = :clientName LIMIT 1");
        $stmt->execute(compact('clientName'));

        if ($client = $stmt->fetch()) {
            $availableGrantTypes = $client['grant_types'];
            $secret = $client['client_secret'];
            $redirectUri = $client['redirect_uri'];
            $clientDisplayName = $client['client_display'];
            $clientID = $client['id'];
            return new ClientEntity($clientID, $clientDisplayName, $redirectUri);
        }
        return null;
    }

    /**
    *   get all clients and scopes with access to a user's account
    */
    public function getClientsAuthorizedByUser($userId) {
        $db = Database::getDatabase(); // pdo instance

        $stmt = $db->prepare("SELECT at.scopes, cl.id as client_id, at.created as date, cl.client_display as name FROM auth3_access_tokens at, auth3_clients cl WHERE at.user_id = :userId AND at.client_id = cl.id AND at.is_revoked = 0 AND at.expires > NOW() GROUP BY cl.id, at.scopes ORDER BY at.expires DESC");
        $stmt->execute(compact('userId'));

        if ($clients = $stmt->fetchAll()) {
            return $clients;
        }
        return null;
    }

    protected function isGrantTypeIncluded($type, $types) {
        return array_search($type, explode(',', $types)) !== false;
    }
}