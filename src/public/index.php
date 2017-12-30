<?php

use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use \Auth3\Database\Database;
use \Auth3\OAuth2;
use \Auth3\OAuth2Resource;
use \Auth3\Config;

require '../../vendor/autoload.php';

/*$config['displayErrorDetails'] = true;
$config['addContentLengthHeader'] = false;
$config['db']['host']   = "localhost";
$config['db']['user']   = "auth3";
$config['db']['pass']   = "auth3";
$config['db']['dbname'] = "auth3";*/

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
    /*$db = $c['settings']['db'];
    $pdo = new PDO("mysql:host=" . $db['host'] . ";dbname=" . $db['dbname'],
        $db['user'], $db['pass']);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    return $pdo;*/
    return $database;
};
$container['view'] = new \Slim\Views\PhpRenderer("../templates/");
$container['oauth_server'] = OAuth2::register([
	"privateKey" => 'J:\BitNami\xampp\htdocs\auth3\keys\private.key',
	//"privateKeyPassPhrase" => "",
	"encryptionKey" => '6kwILTHs88Z2dCWgoyc3gx5d8Dl7QGPBjrVfhixzsSE='
]);
$oauth_resource_server_middleware = new \League\OAuth2\Server\Middleware\ResourceServerMiddleware(OAuth2Resource::register([
	"publicKey" => 'J:\BitNami\xampp\htdocs\auth3\keys\public.key'
]));

$app->get('/', function(Request $request, Response $response) {

	$g = new \GAuth\Auth();
	$code = $g->generateCode();
	echo ($code);

	$response = $this->view->render($response, "login.phtml");
    return $response;
});

/** Create a new user
* POST => [email,password,g-recaptcha-response]
*/
$app->post('/api/users/new', function(Request $request, Response $response) {
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
    $tokenId = $request->getAttribute('id');
    
    $accessTokenRepository = new \Auth3\Repositories\AccessTokenRepository();
    $accessTokenRepository->revokeAccessTokenById($tokenId);

    $json = [
        'message' => "Revoked access token."
    ];
    $response = $response->withJson($json);
    return $response;
});

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

/** 
*   validate a token
*/
$app->map(['GET', 'POST'], '/api/token/validate', function(Request $request, Response $response) {
	return $response;
})->add($oauth_resource_server_middleware);
/** Handle authorize request
* GET -> [response_type, client_id, redirect_uri, scope, state]
*/
$app->get('/api/authorize', function(Request $request, Response $response) {
	$server = $this->oauth_server;

	$authRequest = $server->validateAuthorizationRequest($request);
        
    // The auth request object can be serialized and saved into a user's session.
    // You will probably want to redirect the user at this point to a login endpoint.    
    session_name('AUTH3_SESSID');
    session_start();

    $_SESSION['authorization_code_request'] = $authRequest;

    $clientRepository = new \Auth3\Repositories\ClientRepository();
    //$client = $clientRepository->getClientEntity($clientId, $grantType, null, false);


    //echo '<pre>';
    //print_r($authRequest);
    //var_dump($this->oauth_server);
    
    $response = $this->view->render($response, "authorize.phtml", []);
    // At this point you should redirect the user to an authorization page.
    // This form will ask the user to approve the client and the scopes requested.
    return $response;
});

// requires resource server
$app->post('/api/authorize/accept', function(Request $request, Response $response) {


	session_name('AUTH3_SESSID');
	session_start();
	$authRequest = $_SESSION['authorization_code_request'];

	/*echo '<pre>';
    print_r($authRequest);
    return;*/

	/*
	If the access token is valid the following attributes will be set on the ServerRequest:
	oauth_access_token_id - the access token identifier
	oauth_client_id - the client identifier
	oauth_user_id - the user identifier represented by the access token
	oauth_scopes - an array of string scope identifiers
	*/

	$user_id = $request['oauth_access_token_id'];

	// Once the user has logged in set the user on the AuthorizationRequest
	$userRepository = new \Auth3\Repositories\UserRepository();
    $user = $userRepository->getUserEntityByIdentifier($user_id);
    $authRequest->setUser($user); // an instance of UserEntityInterface
    
    // Once the user has approved or denied the client update the status
    // (true = approved, false = denied)
    $authRequest->setAuthorizationApproved(true);

    // Return the HTTP redirect response
    $res = $server->completeAuthorizationRequest($authRequest, $response);
    $logRepository = new \Auth3\Repositories\EventLogRepository();
    $logRepository->addEvent(new \Auth3\Entities\EventLogEntity('user', 'auth', $_SERVER['REMOTE_ADDR'], $user->getIdentifier()));
    unset($_SESSION['authorization_code_request']);
    session_destroy();

    return $res;
})->add($oauth_resource_server_middleware);

// requires resource server
$app->post('/api/authorize/deny', function(Request $request, Response $response) {


    session_name('AUTH3_SESSID');
    session_start();
    $authRequest = $_SESSION['authorization_code_request'];

    $user_id = $request['oauth_access_token_id'];

    // Once the user has logged in set the user on the AuthorizationRequest
    $userRepository = new \Auth3\Repositories\UserRepository();
    $authRequest->setUser($userRepository->getUserEntityByIdentifier($user_id)); // an instance of UserEntityInterface
    
    // Once the user has approved or denied the client update the status
    // (true = approved, false = denied)
    $authRequest->setAuthorizationApproved(false);

    // Return the HTTP redirect response
    $res = $server->completeAuthorizationRequest($authRequest, $response);
    unset($_SESSION['authorization_code_request']);
    session_destroy();

    return $res;
})->add($oauth_resource_server_middleware);

/** Check if user exists and fetch all account info
* HEADER => [Authorization]
*/
$app->get('/api/user/info', function(Request $request, Response $response) {
    $userRepository = new \Auth3\Repositories\UserRepository();
    $userData = $userRepository->getUserEntityByIdentifier($request->getAttribute('oauth_user_id'));
    if ($userData != null) {
        $json = [
            'firstname' => $userData->getFirstname(),
            'familyname' => $userData->getFamilyname(),
            'email' => $userData->getEmail(),
            'image' => 'https://www.gravatar.com/avatar/'.md5($userData->getEmail()).'?d=retro&r=r',
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

    $response = $response->withJson($json);
    return $response;
})->add($oauth_resource_server_middleware);

/**
*   get two-factor qr data before enabling 2fa
*/
$app->get('/api/user/security/twofactor', function(Request $request, Response $response) {
    $userRepository = new \Auth3\Repositories\UserRepository();
    $userId = $request->getAttribute('oauth_user_id');
    $userData = $userRepository->getUserEntityByIdentifier($userId);
    $size = $request->getParam('size');
    if ($size == null) {
        $size = 30;
    }
    
    if ($userData->hasTwoFactor()) {
        $json = [
            'error' => 'Two-factor authentication is already enabled for this user.'
        ];
    } else {
        $g = new \GAuth\Auth();

        $secret = $userData->getGoogleAuthenticatorCode();
        if ($secret == '') {
            $secret = $g->generateCode();
            // set twofactor in auth3_users to a new unique code
            $userRepository->setTwoFactorForUser($userId, $secret);
        }
        $g->setInitKey($secret);
        $qrImage = \Auth3\Util\TwoFactor::generateQrImage($userData->getEmail(), 'Auth3', $g->getInitKey(), $size);
        $json = [
            'qr_image' => 'data:image/png;base64,'.base64_encode($qrImage),
            'qr_secret' => $secret
        ];
    }

    $response = $response->withJson($json);
    return $response;
})->add($oauth_resource_server_middleware);

$app->post('/api/user/security/twofactor', function(Request $request, Response $response) {
    $userRepository = new \Auth3\Repositories\UserRepository();
    $logRepository = new \Auth3\Repositories\EventLogRepository();
    $userId = $request->getAttribute('oauth_user_id');
    $userData = $userRepository->getUserEntityByIdentifier($userId);

    $authcode = $request->getParsedBodyParam('authcode');
    $secret = $userData->getGoogleAuthenticatorCode();
    if ($secret == '') {
        $json = [
            'error' => "This user does not have a twofactor secret."
        ];
    } else if (strlen($authcode) != 6) {
        $json = [
            'error' => "Auth code is incorrectly formatted."
        ];
    } else {
        $g = new \GAuth\Auth($secret);
        if (!$g->validateCode($authcode)) {
            $json = [
                'error' => "Auth code is invalid."
            ];
        } else {
            $codes = \Auth3\Util\TwoFactor::generateRecoveryCodes(10);
            $codeRepository = new \Auth3\Repositories\RecoveryCodeRepository();
            if ($codeRepository->addCodesForUser($userId, $codes)) {
                $userRepository->setUsingTwoFactorForUser($userId, true);
                $logRepository->addEvent(new \Auth3\Entities\EventLogEntity('user', 'twofactor', $_SERVER['REMOTE_ADDR'] . ' enabled 2-factor authentication', $userId));
                $json = [
                    'recovery_codes' => $codes
                ];
            } else {
                $json = [
                    'error' => "Failed to set recovery codes"
                ];
            }
        }
    }
    return $response->withJson($json);
})->add($oauth_resource_server_middleware);

$app->delete('/api/user/security/twofactor', function(Request $request, Response $response) {
    $userRepository = new \Auth3\Repositories\UserRepository();
    $logRepository = new \Auth3\Repositories\EventLogRepository();
    $codeRepository = new \Auth3\Repositories\RecoveryCodeRepository();
    $userId = $request->getAttribute('oauth_user_id');
    $userData = $userRepository->getUserEntityByIdentifier($userId);

    //$authcode = $request->getParsedBodyParam('authcode');
    $secret = $userData->getGoogleAuthenticatorCode();
    if ($secret == '') {
        $json = [
            'error' => "This user does not have a twofactor secret."
        ];
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

$app->get('/api/user/security/twofactor/codes', function(Request $request, Response $response) {
    $userId = $request->getAttribute('oauth_user_id');
    $codeRepository = new \Auth3\Repositories\RecoveryCodeRepository();
    $codes = $codeRepository->getCodesForUser($userId);
    $json = [
        'recovery_codes' => $codes
    ];
    return $response->withJson($json);
})->add($oauth_resource_server_middleware);

$app->any('/test', function(Request $request, Response $response) {
    $json = [
        'oauth_access_token_id' => $request->getAttribute('oauth_access_token_id'),
        'oauth_client_id' => $request->getAttribute('oauth_client_id'),
        'oauth_user_id' => $request->getAttribute('oauth_user_id'),
        'oauth_scopes' => $request->getAttribute('oauth_scopes'),
    ];
    $response = $response->withJson($json);
    return $response;
})->add($oauth_resource_server_middleware);

$app->options('/{routes:.+}', function ($request, $response, $args) {
    return $response;
});
$app->add(function($req, $res, $next) {
    $response = $next($req, $res);
    return $response
            ->withHeader('Access-Control-Allow-Origin', 'http://localhost:3000')
            ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
            ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
});

$app->run();