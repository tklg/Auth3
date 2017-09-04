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

           if ($mustValidateSecret && $secret !== $clientSecret) return null;

           if ($this->isGrantTypeIncluded($grantType, $availableGrantTypes)) {
                return new ClientEntity($clientID, $clientDisplayName, $redirectUri);
           }
        }
        return null;
    }

    protected function isGrantTypeIncluded($type, $types) {
        return array_search($type, explode(',', $types)) !== false;
    }
}