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
	/* @var \League\OAuth2\Server\AuthorizationServer $server */
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

$app->any('/api/token/validate', function(Request $request, Response $response) {
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
    $authRequest->setUser($userRepository->getUserEntityByIdentifier($user_id)); // an instance of UserEntityInterface
    
    // Once the user has approved or denied the client update the status
    // (true = approved, false = denied)
    $authRequest->setAuthorizationApproved(true);

    // Return the HTTP redirect response
    $res = $server->completeAuthorizationRequest($authRequest, $response);
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
$app->get('/users/{email}', function(Request $request, Response $response) {
    $email = $request->getAttribute('email');
    $headers = $request->getHeaders();
    echo $email;
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