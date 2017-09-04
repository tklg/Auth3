<?php

use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use \Auth3\Database\Database;
use \Auth3\OAuth2;

require '../../vendor/autoload.php';

$config['displayErrorDetails'] = true;
$config['addContentLengthHeader'] = false;
$config['db']['host']   = "localhost";
$config['db']['user']   = "auth3";
$config['db']['pass']   = "auth3";
$config['db']['dbname'] = "auth3";

$app = new \Slim\App(["settings" => $config]);
$container = $app->getContainer();

$container['logger'] = function($c) {
    $logger = new \Monolog\Logger('my_logger');
    $file_handler = new \Monolog\Handler\StreamHandler("../logs/app.log");
    $logger->pushHandler($file_handler);
    return $logger;
};

$database = Database::register($container['settings']['db']);
$oauth_server = OAuth2::register([
	"privateKey" => 'J:\BitNami\xampp\htdocs\auth3\keys\private.key',
	//"privateKeyPassPhrase" => "",
	"encryptionKey" => '6kwILTHs88Z2dCWgoyc3gx5d8Dl7QGPBjrVfhixzsSE='
]);

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

	return $response;
});
/** Check if user exists and fetch basic account info
* HEADER => [Authorization]
*/
$app->get('/api/users/{email}', function(Request $request, Response $response) {
	$email = $request->getAttribute('email');
	$headers = $request->getHeaders();
	// if Authorization header is valid, return full account data
	// else return name, profile picture

	return $response;
});
/** Handle login attempt
* POST => [grant_type,client_id,client_secret,scope,username,password,authcode]
*/
$app->any('/token', function(Request $request, Response $response) use ($oauth_server) {
	/* @var \League\OAuth2\Server\AuthorizationServer $server */
    $server = $oauth_server;

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

$app->get('/authorize', function(Request $request, Response $response) {

	return $response;
});

$app->run();