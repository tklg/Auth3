<?php

use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use \Auth3\Database\Database;
use \Auth3\OAuth2;
use \Auth3\OAuth2Resource;
use \Auth3\Config;
use \Auth3\Util\TwoFactor;

require '../../vendor/autoload.php';

$config = Config::getConfig();

$app = new \Slim\App(["settings" => $config]);
$container = $app->getContainer();

$container['logger'] = function($c) {
    $logger = new \Monolog\Logger('auth3_logger');
    $file_handler = new \Monolog\Handler\StreamHandler("../logs/app.log");
    $logger->pushHandler($file_handler);
    return $logger;
};

$database = Database::register($container['settings']['db']);

$container['db'] = function ($c) {
    return $database;
};
$container['view'] = new \Slim\Views\PhpRenderer("../templates/");
$container['oauth_server'] = OAuth2::register([
	"privateKey" => $config['privateKey'],
	//"privateKeyPassPhrase" => "",
	"encryptionKey" => $config['encryptionKey']
]);
$oauth_resource_server_middleware = new \League\OAuth2\Server\Middleware\ResourceServerMiddleware(OAuth2Resource::register([
	"publicKey" => $config['publicKey']
]));

$app->get('/[login]', function(Request $request, Response $response) {
	return $this->view->render($response, "index.html");
});
$app->get('/account', function(Request $request, Response $response) {
    return $this->view->render($response, "account.html");
});
$app->get('/signup', function(Request $request, Response $response) {
    return $this->view->render($response, "signup.phtml", ['captchaSiteKey' => \Auth3\Config::getConfig()['captcha']['public']]);
});
$app->get('/forgot', function(Request $request, Response $response) {
    return $this->view->render($response, "forgot.phtml", ['captchaSiteKey' => \Auth3\Config::getConfig()['captcha']['public']]);
});
$app->get('/recover', function(Request $request, Response $response) {
    $data = [
        'email' => $request->getParam('from'),
        'key' => $request->getParam('key')
    ];
    return $this->view->render($response, "recover.phtml", $data);
});
$app->get('/authorize', function(Request $request, Response $response) {
    return $this->view->render($response, "authorize.html");
});
$app->group('/about', function() {
    $this->get('/terms', function(Request $request, Response $response) {
        return $this->view->render($response, "terms.html");
    });
    $this->get('/privacy', function(Request $request, Response $response) {
        return $this->view->render($response, "privacy.html");
    });
    $this->get('/help', function(Request $request, Response $response) {
        return $this->view->render($response, "help.html");
    });
});

/** Create a new user
* POST => [email,password,g-recaptcha-response]
*/
$app->post('/api/user/new', function(Request $request, Response $response) {
    $userRepository = new \Auth3\Repositories\UserRepository();
    $email = $request->getParsedBodyParam('email');
    $password = $request->getParsedBodyParam('password');
    $recaptcha = $request->getParsedBodyParam('g-recaptcha-response');
    $result = $userRepository->createUser($email, $password, $recaptcha);
    if ($result['error'] != 'success') {
        $json = $result;
    } else {
        $json = [
            'firstname' => $result['user']->getFirstname(),
            'familyname' => $result['user']->getFamilyname(),
            'email' => $result['user']->getEmail(),
            'image' => 'https://www.gravatar.com/avatar/'.md5($result['user']->getEmail()).'?d=retro&r=r'
        ];
        $email = new \Auth3\Util\Email();
        $email->setTo($result['user']->getEmail());
        $email->setFrom('Auth3 <auth3@tkluge.net>');
        $email->setSubject('Email verification');
        $link = 'http://'.$_SERVER['HTTP_HOST']."/api/verify?key=".$result['user']->getEmailVerification().'&from='.$result['user']->getEmail();
        $email->setText('Hello, ' . $result['user']->getEmail() . '! Use this link to verify your email address: ' . $link);
        try {
            $result = $email->send();
            $json['message'] = 'Email sent';
            $json['mailgun_response'] = $result;
        } catch (Exception $e) {
            $json['error'] = $e->getMessage();
        }
    }
    $response = $response->withJson($json);
	return $response;
});
/**
* Check if an email is taken
*/
$app->get('/api/exists/{email}', function(Request $request, Response $response) {
    $email = $request->getAttribute('email');
    // if Authorization header is valid, return full account data
    // else return name, profile picture
    $userRepository = new \Auth3\Repositories\UserRepository();
    $userData = $userRepository->getUserEntityByEmail($email);
    //print_r($userData);
    if ($userData != null) {
        $json = [
            'firstname' => $userData->getFirstname(),
            'familyname' => $userData->getFamilyname(),
            'email' => $userData->getEmail(),
            'image' => 'https://www.gravatar.com/avatar/'.md5($userData->getEmail()).'?d=retro&r=r'
        ];
    } else {
        $json = [
            'status' => 'error',
            'message' => 'No user with this email exists.'
        ];
    }
    $response = $response->withJson($json);
    return $response;
});
/** Handle token request
* POST => [grant_type,client_id,client_secret,scope,username,password,authcode]
*/
$app->post('/api/token', function(Request $request, Response $response) {
    // http://ipinfodb.com/ip_location_api.php
    // http://www.hostip.info/index.html?spip=0.0.0.0
    $server = $this->oauth_server;

    try {
        // Try to respond to the request
        $response = $server->respondToAccessTokenRequest($request, $response);

        return $response;
    } catch (\League\OAuth2\Server\Exception\OAuthServerException $exception) {
        // All instances of OAuthServerException can be formatted into a HTTP response
        return $exception->generateHttpResponse($response); 
    /*} catch (\Auth3\Exception\Auth3Exception $exception) {
        return $exception->generateHttpResponse($response);*/
    } catch (\Exception $exception) {
        // Unknown exception
        $body = $response->getBody();
        $body->write($exception->getMessage());
        return $response->withStatus(500);/*->withBody($body);*/
        
    }
});

/** 
*   delete an auth token
*/
$app->delete('/api/token/{id}', function(Request $request, Response $response) {
    if (!\Auth3\Util\VerifyScopes::verify(['user.all'], $request->getAttribute('oauth_scopes'))) {
        return $response->withJson(['error' => "Insufficient scope."], 401);
    }
    $tokenId = $request->getAttribute('id');
    
    $accessTokenRepository = new \Auth3\Repositories\AccessTokenRepository();
    $accessTokenRepository->revokeAccessTokenById($tokenId);

    $json = [
        'message' => "Revoked access token."
    ];
    $response = $response->withJson($json);
    return $response;
})->add($oauth_resource_server_middleware);

/** 
*   delete all tokens for a client
*/
$app->delete('/api/client_token/{id}', function(Request $request, Response $response) {
    if (!\Auth3\Util\VerifyScopes::verify(['user.all'], $request->getAttribute('oauth_scopes'))) {
        return $response->withJson(['error' => "Insufficient scope."], 401);
    }
    $clientId = $request->getAttribute('id');
    
    $accessTokenRepository = new \Auth3\Repositories\AccessTokenRepository();
    $accessTokenRepository->revokeAccessTokenByClientId($clientId, $request->getAttribute('oauth_user_id'));

    $json = [
        'message' => "Revoked access token(s)."
    ];
    $response = $response->withJson($json);
    return $response;
})->add($oauth_resource_server_middleware);

/**
* log the user out by revoking the current token
*/
$app->get('/api/logout', function(Request $request, Response $response) {
    $tokenId = $request->getAttribute('oauth_access_token_id');
    
    $accessTokenRepository = new \Auth3\Repositories\AccessTokenRepository();
    $accessTokenRepository->revokeAccessToken($tokenId);

    $json = [
        'message' => "Revoked access token."
    ];
    $response = $response->withJson($json);
    return $response;
})->add($oauth_resource_server_middleware);

/** Handle authorize request
* GET -> [response_type, client_id, redirect_uri, scope, state]
*/
$app->get('/api/authorize', function(Request $request, Response $response) {
    if (!\Auth3\Util\VerifyScopes::verify(['user.all'], $request->getAttribute('oauth_scopes'))) {
        return $response->withJson(['error' => "Insufficient scope."], 401);
    }
	$server = $this->oauth_server;

    $userId = $request->getAttribute('oauth_user_id');
    // Once the user has logged in set the user on the AuthorizationRequest
    $userRepository = new \Auth3\Repositories\UserRepository();
    $clientRepository = new \Auth3\Repositories\ClientRepository();
    try {
        $authRequest = $server->validateAuthorizationRequest($request);
        $user = $userRepository->getUserEntityByIdentifier($userId);
        $client = $clientRepository->getClientEntityByName($request->getParam('client_id'));
        if ($user == null) {
            return $response->withJson(['error' => 'User does not exist'], 404);
        } 
        if ($client == null) {
            return $response->withJson(['error' => 'Client does not exist'], 404);
        }
        $authRequest->setUser($user); // an instance of UserEntityInterface
            
        // The auth request object can be serialized and saved into a user's session.
        // You will probably want to redirect the user at this point to a login endpoint.    
        session_name('AUTH3_SESSID');
        session_start();

        $_SESSION['auth3_authorization_code_request'] = $authRequest;
        $_SESSION['auth3_user'] = $user;
        $_SESSION['auth3_client'] = $client;
        //$response = $this->view->render($response, "authorize.phtml", []);
        $json = [
            'session' => session_id(),
            'application' => $client->getName(),
            'scopes' => explode(" ", $request->getParam('scope'))
        ];
        // At this point you should redirect the user to an authorization page.
        // This form will ask the user to approve the client and the scopes requested.
        return $response->withJson($json);
    } catch (\League\OAuth2\Server\Exception\OAuthServerException $exception) {
        // dont actually return the redirect, as these are ajax requests
        //return $exception->generateHttpResponse($response);
        $client = $clientRepository->getClientEntityByName($request->getParam('client_id'));
        if ($client == null) {
            return $response->withJson(['error' => 'Client does not exist'], 404);
        }
        return $response->withJson([
            'error' => $exception->getErrorType(), 
            'message' => $exception->getMessage(),
            'hint' => $exception->getHint(),
            'redirect_uri' => $client->getRedirectUri()
        ])->withStatus(500);
    } 
})->add($oauth_resource_server_middleware);

/**
*   Accept authorization request
*/
$app->get('/api/authorize/accept', function(Request $request, Response $response) {
    $logRepository = new \Auth3\Repositories\EventLogRepository();
    $server = $this->oauth_server;
	session_name('AUTH3_SESSID');
    session_id($request->getParam('session'));
	session_start();
	$authRequest = $_SESSION['auth3_authorization_code_request']; 
    $user = $_SESSION['auth3_user'];
    $client = $_SESSION['auth3_client'];
    $authRequest->setAuthorizationApproved(true);
    unset($_SESSION['auth3_authorization_code_request']);
    unset($_SESSION['auth3_user']);
    unset($_SESSION['auth3_client']);
    session_destroy();
    try {
        $response = $server->completeAuthorizationRequest($authRequest, $response);
        $logRepository->addEvent(new \Auth3\Entities\EventLogEntity('user', 'auth', $_SERVER['REMOTE_ADDR'] . ' authorized ' . $client->getName(), $user->getIdentifier()));
        return $response;
    } catch (\League\OAuth2\Server\Exception\OAuthServerException $exception) {
        return $exception->generateHttpResponse($response);
    }
});

/**
*   Deny authorization request
*/
$app->get('/api/authorize/deny', function(Request $request, Response $response) {
    $server = $this->oauth_server;
    session_name('AUTH3_SESSID');
    session_id($request->getParam('session'));
    session_start();
    $authRequest = $_SESSION['auth3_authorization_code_request'];
    $user = $_SESSION['auth3_user'];
    $client = $_SESSION['auth3_client'];
    $authRequest->setAuthorizationApproved(false);
    unset($_SESSION['auth3_authorization_code_request']);
    unset($_SESSION['auth3_user']);
    unset($_SESSION['auth3_client']);
    session_destroy();
    try {
        $response = $server->completeAuthorizationRequest($authRequest, $response);
        return $response;
    } catch (\League\OAuth2\Server\Exception\OAuthServerException $exception) {
        return $exception->generateHttpResponse($response);
    }
});
/** Check if user exists and fetch all account info
* HEADER => [Authorization]
*/
$app->get('/api/user/info', function(Request $request, Response $response) {
    if (!\Auth3\Util\VerifyScopes::verify(['user.email', 'user.name'], $request->getAttribute('oauth_scopes'))) {
        return $response->withJson(['error' => "Insufficient scope."], 401);
    }
    $userRepository = new \Auth3\Repositories\UserRepository();
    $userData = $userRepository->getUserEntityByIdentifier($request->getAttribute('oauth_user_id'));
    if ($userData != null) {
        $json = [
            'uuid' => $userData->getUUID(),
            'firstname' => $userData->getFirstname(),
            'familyname' => $userData->getFamilyname(),
            'email' => $userData->getEmail(),
            'image' => 'https://www.gravatar.com/avatar/'.md5($userData->getEmail()).'?d=retro&r=r&s=60',
            'joindate' => $userData->getJoinDate(),
            'verified' => $userData->getEmailVerification() == 'verified' ? 'verified' : 'not verified'
        ];
    } else {
        $json = [
            'status' => 'error',
            'message' => 'No user with this token exists.'
        ];
    }

    $response = $response->withJson($json);
    return $response;
})->add($oauth_resource_server_middleware);

/**
* return user security details (2fa, sessions, history)
*/
$app->get('/api/user/security', function(Request $request, Response $response) {
    if (!\Auth3\Util\VerifyScopes::verify(['user.all'], $request->getAttribute('oauth_scopes'))) {
        return $response->withJson(['error' => "Insufficient scope."], 401);
    }
    $userRepository = new \Auth3\Repositories\UserRepository();
    $accessTokenRepository = new \Auth3\Repositories\AccessTokenRepository();
    $logRepository = new \Auth3\Repositories\EventLogRepository();
    $userId = $request->getAttribute('oauth_user_id');
    $userData = $userRepository->getUserEntityByIdentifier($userId);
    $tokens = $accessTokenRepository->getAccessTokensByUserId($userId, $request->getAttribute('oauth_access_token_id'));
    $history = $logRepository->getEventsByUserId($userId);

    $json = [
        'hasTwoFactor' => $userData->hasTwoFactor(),
        'sessions' => $tokens,
        'history' => $history
    ];

    $response = $response->withJson($json);
    return $response;
})->add($oauth_resource_server_middleware);

/**
*   return user's authorized applications
*/
$app->get('/api/user/applications', function(Request $request, Response $response) {
    if (!\Auth3\Util\VerifyScopes::verify(['user.all'], $request->getAttribute('oauth_scopes'))) {
        return $response->withJson(['error' => "Insufficient scope."], 401);
    }
    $appRepository = new \Auth3\Repositories\ClientRepository();
    $userId = $request->getAttribute('oauth_user_id');
    $apps = $appRepository->getClientsAuthorizedByUser($userId);
    if ($apps == null) $apps = [];
    $json = [
        'applications' => $apps
    ];

    $response = $response->withJson($json);
    return $response;
})->add($oauth_resource_server_middleware);

/**
*   update user info
*/
$app->post('/api/user/info', function(Request $request, Response $response) {
    if (!\Auth3\Util\VerifyScopes::verify(['user.all'], $request->getAttribute('oauth_scopes'))) {
        return $response->withJson(['error' => "Insufficient scope."], 401);
    }
    $userId = $request->getAttribute('oauth_user_id');
    $userRepository = new \Auth3\Repositories\UserRepository();

    function buildFromParams(Request $req, array $plist) {
        $res = [];
        foreach ($plist as $param) {
            $d = $req->getParsedBodyParam($param);
            if (isset($d)) $res[$param] = $d;
        }
        return $res;
    }
    $data = buildFromParams($request, ['firstname', 'familyname', 'email', 'password_old', 'password_new', 'password_confirm']);
    if (sizeof($data) == 0) $json = ['error', 'Request is empty.'];
    else $json = $userRepository->updateUser($userId, $data);
    if (isset($json['error'])) {
        $response = $response->withJson($json, 401);
    } else {
        $response = $response->withJson($json);
    }
    return $response;
})->add($oauth_resource_server_middleware);

/**
*   get two-factor qr data before enabling 2fa
*/
$app->get('/api/user/security/twofactor', function(Request $request, Response $response) {
    if (!\Auth3\Util\VerifyScopes::verify(['user.all'], $request->getAttribute('oauth_scopes'))) {
        return $response->withJson(['error' => "Insufficient scope."], 401);
    }
    $userRepository = new \Auth3\Repositories\UserRepository();
    $userId = $request->getAttribute('oauth_user_id');
    $userData = $userRepository->getUserEntityByIdentifier($userId);
    
    if ($userData->hasTwoFactor()) {
        $json = [
            'error' => 'Two-factor authentication is already enabled for this user.'
        ];
    } else {
        $secret = $userData->getGoogleAuthenticatorCode();
        if ($secret == '') {
            $secret = TwoFactor::createSecret();
            // set twofactor in auth3_users to a new unique code
            $userRepository->setTwoFactorForUser($userId, $secret);
        }
        $qrImage = TwoFactor::generateQrImage($userData->getEmail(), 'Auth3', $secret);
        $json = [
            'qr_image' => 'data:image/png;base64,'.base64_encode($qrImage),
            'qr_secret' => $secret
        ];
    }

    $response = $response->withJson($json);
    return $response;
})->add($oauth_resource_server_middleware);

/**
*   enable 2FA
*/
$app->post('/api/user/security/twofactor/enable', function(Request $request, Response $response) {
    if (!\Auth3\Util\VerifyScopes::verify(['user.all'], $request->getAttribute('oauth_scopes'))) {
        return $response->withJson(['error' => "Insufficient scope."], 401);
    }
    $userRepository = new \Auth3\Repositories\UserRepository();
    $logRepository = new \Auth3\Repositories\EventLogRepository();
    $userId = $request->getAttribute('oauth_user_id');
    $userData = $userRepository->getUserEntityByIdentifier($userId);

    $authcode = $request->getParsedBodyParam('authcode');
    $secret = $userData->getGoogleAuthenticatorCode();
    if ($secret == '') {
        return $response->withJson([
            'error' => "This user does not have a twofactor secret."
        ], 401);
    } else if (strlen($authcode) != 6) {
        return $response->withJson([
            'error' => "Auth code is incorrectly formatted."
        ], 401);
    } else {
        if (!TwoFactor::verify($secret, $authcode)) {
            return $response->withJson([
                'error' => "Auth code is invalid."
            ], 401);
        } else {
            $codes = TwoFactor::generateRecoveryCodes(10);
            $codeRepository = new \Auth3\Repositories\RecoveryCodeRepository();
            if ($codeRepository->addCodesForUser($userId, $codes)) {
                $userRepository->setUsingTwoFactorForUser($userId, true);
                $logRepository->addEvent(new \Auth3\Entities\EventLogEntity('user', 'twofactor', $_SERVER['REMOTE_ADDR'] . ' enabled 2-factor authentication', $userId));
                return $response->withJson([
                    'recovery_codes' => $codes
                ]);
            } else {
                return $response->withJson([
                    'error' => "Failed to set recovery codes"
                ], 500);
            }
        }
    }
})->add($oauth_resource_server_middleware);

/**
*   disable 2FA
*/
$app->post('/api/user/security/twofactor/disable', function(Request $request, Response $response) {
    if (!\Auth3\Util\VerifyScopes::verify(['user.all'], $request->getAttribute('oauth_scopes'))) {
        return $response->withJson(['error' => "Insufficient scope."], 401);
    }
    $userRepository = new \Auth3\Repositories\UserRepository();
    $logRepository = new \Auth3\Repositories\EventLogRepository();
    $codeRepository = new \Auth3\Repositories\RecoveryCodeRepository();
    $userId = $request->getAttribute('oauth_user_id');
    $user = $userRepository->getUserEntityByIdentifier($userId);
    $password = $request->getParam('password');
    $secret = $user->getGoogleAuthenticatorCode();
    // not good, fix
    if ($userRepository->getUserEntityByUserCredentials($user->getEmail(), $password, null, new \Auth3\Entities\ClientEntity(null, null, null)) == null) {
        return $response->withJson(['error' => 'Password is incorrect.'], 401);
    } else if ($secret == '') {
        return $response->withJson([
            'error' => "This user does not have a twofactor secret."
        ], 401);
    } else {
        $userRepository->setTwoFactorForUser($userId, '');
        $userRepository->setUsingTwoFactorForUser($userId, false);
        $codeRepository->removeCodesForUser($userId);
        $logRepository->addEvent(new \Auth3\Entities\EventLogEntity('user', 'twofactor', $_SERVER['REMOTE_ADDR'] . ' disabled 2-factor authentication', $userId));
        $json = [
            'message' => "Twofactor disabled."
        ];
    }
    return $response->withJson($json);
})->add($oauth_resource_server_middleware);

/**
*   fetch 2FA recovery codes
*/
$app->post('/api/user/security/twofactor/codes', function(Request $request, Response $response) {
    if (!\Auth3\Util\VerifyScopes::verify(['user.all'], $request->getAttribute('oauth_scopes'))) {
        return $response->withJson(['error' => "Insufficient scope."], 401);
    }
    $codeRepository = new \Auth3\Repositories\RecoveryCodeRepository();
    $userRepository = new \Auth3\Repositories\UserRepository();
    $userId = $request->getAttribute('oauth_user_id');
    $password = $request->getParam('password');
    $user = $userRepository->getUserEntityByIdentifier($userId);
    $secret = $user->getGoogleAuthenticatorCode();
    // not good, fix
    if ($userRepository->getUserEntityByUserCredentials($user->getEmail(), $password, null, new \Auth3\Entities\ClientEntity(null, null, null)) == null) {
        return $response->withJson(['error' => 'Password is incorrect.'], 401);
    } else if ($secret == '') {
        return $response->withJson([
            'error' => "This user does not have a twofactor secret."
        ], 401);
    }
    $codes = $codeRepository->getCodesForUser($userId);
    $json = [
        'recovery_codes' => $codes
    ];
    return $response->withJson($json);
})->add($oauth_resource_server_middleware);

/**
*   regenerate 2FA recovery codes
*/
$app->post('/api/user/security/twofactor/codes/regen', function(Request $request, Response $response) {
    if (!\Auth3\Util\VerifyScopes::verify(['user.all'], $request->getAttribute('oauth_scopes'))) {
        return $response->withJson(['error' => "Insufficient scope."], 401);
    }
    $codeRepository = new \Auth3\Repositories\RecoveryCodeRepository();
    $userRepository = new \Auth3\Repositories\UserRepository();
    $codeRepository = new \Auth3\Repositories\RecoveryCodeRepository();
    $logRepository = new \Auth3\Repositories\EventLogRepository();

    $userId = $request->getAttribute('oauth_user_id');
    $password = $request->getParam('password');
    $user = $userRepository->getUserEntityByIdentifier($userId);
    $secret = $user->getGoogleAuthenticatorCode();
    // not good, fix
    if ($userRepository->getUserEntityByUserCredentials($user->getEmail(), $password, null, new \Auth3\Entities\ClientEntity(null, null, null)) == null) {
        return $response->withJson(['error' => 'Password is incorrect.'], 401);
    } else if ($secret == '') {
        return $response->withJson([
            'error' => "This user does not have a twofactor secret."
        ], 401);
    }
    $codeRepository->removeCodesForUser($userId);
    $codes = \Auth3\Util\TwoFactor::generateRecoveryCodes(10);
    if ($codeRepository->addCodesForUser($userId, $codes)) {
        $logRepository->addEvent(new \Auth3\Entities\EventLogEntity('user', 'twofactor', $_SERVER['REMOTE_ADDR'] . ' regenerated recovery codes', $userId));
        return $response->withJson([
            'recovery_codes' => $codes
        ]);
    } else {
        return $response->withJson([
            'error' => "Failed to set recovery codes"
        ], 500);
    }
})->add($oauth_resource_server_middleware);

/**
*   send email verification code to user's email
*/
$app->post('/api/sendverification', function(Request $request, Response $response) {
    if (!\Auth3\Util\VerifyScopes::verify(['user.all'], $request->getAttribute('oauth_scopes'))) {
        return $response->withJson(['error' => "Insufficient scope."], 401);
    }
    $userRepository = new \Auth3\Repositories\UserRepository();
    $userId = $request->getAttribute('oauth_user_id');
    $userData = $userRepository->getUserEntityByIdentifier($userId);

    if ($userData->getEmail() == 'test@test.test') {
        return $response->withJson(['error' => "Cannot verify the test email."], 401);
    }

    $email = new \Auth3\Util\Email();
    $email->setTo($userData->getEmail());
    $email->setFrom('Auth3 <auth3@tkluge.net>');
    $email->setSubject('Email verification');
    $link = 'http://'.$_SERVER['HTTP_HOST']."/api/verify?key=".$userData->getEmailVerification().'&from='.$userData->getEmail();
    $email->setText('Hello, ' . $userData->getEmail() . '! Use this link to verify your email address: ' . $link);
    try {
        $result = $email->send();
        $json = [
            'message' => 'Email sent',
            'mailgun_response' => $result
        ];
    } catch (Exception $e) {
        $json = [
            'error' => $e->getMessage()
        ];
        $response = $response->withStatus(500);
    }
    return $response->withJson($json);
})->add($oauth_resource_server_middleware);

/**
*   validate an email verification key
*/
$app->get('/api/verify', function(Request $request, Response $response) {
    $userRepository = new \Auth3\Repositories\UserRepository();

    $key = $request->getParam('key');
    $email = $request->getParam('from');
    if ($email == null) {
        $json = [
            'error' => "Missing parameter: `from`"
        ];
        return $response->withJson($json, 400);
    } else if ($key == null || strlen($key) != 40) {
        $json = [
            'error' => "Missing valid parameter value: `key`"
        ];
        return $response->withJson($json, 400);
    } else {
        $userData = $userRepository->getUserEntityByEmail($email);
        if ($userData == null) {
            $json = [
                'error' => "User does not exist: " . $email
            ];
            return $response->withJson($json, 404);
        } else {
            if ($userData->getEmailVerification() == $key) {
                $userRepository->setEmailVerificationForUser($userData->getIdentifier(), true);
                return $response->withRedirect('http://' . $_SERVER['HTTP_HOST'].'/account', 302);
            } else {
                $json = [
                    'error' => "That key is not valid."
                ];
                return $response->withJson($json, 400);
            }
        }
    }
});

$app->post('/api/user/recover', function(Request $request, Response $response) {
    $userRepository = new \Auth3\Repositories\UserRepository();
    $recoveryCodeRepository = new \Auth3\Repositories\PasswordRecoveryCodeRepository();
    $email = $request->getParsedBodyParam('email');
    $user = $userRepository->getUserEntityByEmail($email);
    $recaptcha = $request->getParsedBodyParam('g-recaptcha-response');
    if ($user != null) {

        // create and save recovery key
        if (function_exists('random_bytes')) {
            $bytes = bin2hex(random_bytes(20));
        } else {
            $bytes = bin2hex(openssl_random_pseudo_bytes(20));
        }
        $recoveryCodeRepository->removeCodesForUser($user->getIdentifier());
        if ($recoveryCodeRepository->addCodeForUser($user->getIdentifier(), $bytes) != null) {
            if (\Auth3\Util\Recaptcha::verify($recaptcha, $_SERVER['HTTP_HOST'])) {
                $email = new \Auth3\Util\Email();
                $email->setTo($user->getEmail());
                $email->setFrom('Auth3 <auth3@tkluge.net>');
                $email->setSubject('Account recovery');
                $link = 'http://'.$_SERVER['HTTP_HOST']."/recover?key=".$bytes.'&from='.$user->getEmail();
                $email->setText('Hello, ' . $user->getEmail() . '! Use this link to reset your password: ' . $link);
                try {
                    $result = $email->send();
                    $json = [
                        'message' => 'Email sent',
                        'mailgun_response' => $result
                    ];
                } catch (Exception $e) {
                    return $response->withJson([
                        'error' => $e->getMessage()
                    ], 500);
                }
            } else {
                return $response->withJson([
                    'error' => 'Invalid recaptcha.'
                ], 401);
            }   
        } else {
            return $response->withJson([
                'error' => 'Failed to generate secret.'
            ], 401);
        }
    } else {
        return $response->withJson([
            'error' => 'A user with that email does not exist.'
        ], 404);
    }
    return $response->withJson($json);
});

$app->post('/api/user/passwordreset', function(Request $request, Response $response) {
    $userRepository = new \Auth3\Repositories\UserRepository();
    $recoveryCodeRepository = new \Auth3\Repositories\PasswordRecoveryCodeRepository();
    $email = $request->getParsedBodyParam('email');
    $key = $request->getParsedBodyParam('key');
    $password = $request->getParsedBodyParam('password');
    $password2 = $request->getParsedBodyParam('password_confirm');
    $user = $userRepository->getUserEntityByEmail($email);
    if ($user != null) {
        if ($recoveryCodeRepository->validateCodeForUser($user->getIdentifier(), $key)) {
            $recoveryCodeRepository->removeCodesForUser($user->getIdentifier());
            $data = [
                'password_new' => $password,
                'password_confirm' => $password2
            ];
            $json = $userRepository->resetUserPassword($user->getIdentifier(), $data);
            if (isset($json['error'])) {
                return $response->withJson($json, 401);
            } else {
                return $response->withJson($json);
            }
        } else {
            return $response->withJson([
                'error' => 'Invalid key.'
            ], 401);
        }
    } else {
        return $response->withJson([
            'error' => 'A user with that email does not exist.'
        ], 404);
    }
});
/** 
*   validate a token
*/
/*$app->map(['GET', 'POST'], '/api/token/validate', function(Request $request, Response $response) {
    return $response;
})->add($oauth_resource_server_middleware);

$app->options('/test', function(Request $request, Response $response) {
    $json = [
        'oauth_access_token_id' => $request->getAttribute('oauth_access_token_id'),
        'oauth_client_id' => $request->getAttribute('oauth_client_id'),
        'oauth_user_id' => $request->getAttribute('oauth_user_id'),
        'oauth_scopes' => $request->getAttribute('oauth_scopes'),
    ];
    $response = $response->withJson($json);
    return $response;
})->add($oauth_resource_server_middleware);*/

$app->options('/{routes:.+}', function ($request, $response, $args) {
    return $response;
});
$app->add(function($req, $res, $next) {
    $response = $next($req, $res);
    return $response
            ->withHeader('Access-Control-Allow-Origin', 'http://localhost:81')
            ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
            ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
});

$app->run();
