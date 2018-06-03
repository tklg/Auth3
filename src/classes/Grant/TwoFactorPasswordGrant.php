<?php
/**
 * OAuth 2.0 Password + 2FA grant.
 *
 * @author      Theodore Kluge
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/villa7/foxfile-core
 */

namespace Auth3\Grant;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use Auth3\Exception\Auth3Exception;

/**
 * Password + 2FA grant class.
 */
class TwoFactorPasswordGrant extends \League\OAuth2\Server\Grant\AbstractGrant {
    /**
     * @param UserRepositoryInterface         $userRepository
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function __construct(
        UserRepositoryInterface $userRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository
    ) {
        $this->setUserRepository($userRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);

        $this->refreshTokenTTL = new \DateInterval('P1M');
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL
    ) {
        // Validate request
        $client = $this->validateClient($request);
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request));
        $user = $this->validateUser($request, $client);


        // Finalize the requested scopes
        $scopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $user->getIdentifier());

        // Issue and persist new tokens
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user->getIdentifier(), $scopes);
        $refreshToken = $this->issueRefreshToken($accessToken);

        // Inject tokens into response
        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        return $responseType;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ClientEntityInterface  $client
     *
     * @throws OAuthServerException
     *
     * @return UserEntityInterface
     */
    protected function validateUser(ServerRequestInterface $request, ClientEntityInterface $client) {
        $username = $this->getRequestParameter('username', $request);
        if (is_null($username)) {
            throw OAuthServerException::invalidRequest('username');
        }

        $password = $this->getRequestParameter('password', $request);
        if (is_null($password)) {
            throw OAuthServerException::invalidRequest('password');
        }

        $logRepository = new \Auth3\Repositories\EventLogRepository();

        $user = $this->userRepository->getUserEntityByUserCredentials(
            $username,
            $password,
            $this->getIdentifier(),
            $client
        );
        if ($user instanceof UserEntityInterface === false) {
            $logRepository->addEvent(new \Auth3\Entities\EventLogEntity('user', 'login-fail', $_SERVER['REMOTE_ADDR'] . ' provided invalid credentials', $this->userRepository->getUserEntityByEmail($username)->getIdentifier()));
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidCredentials();
        }


        // check if user has 2fa enabled
        if ($user->hasTwoFactor()) {

            $authcode = $this->getRequestParameter('authcode', $request);
            $usingRecovery = false;
            if (is_null($authcode)) {
                throw Auth3Exception::invalidTwoFactor('missing');
            }
            $authcode = preg_replace('/[^0-9a-zA-Z]/', '', $authcode);
            if (strlen($authcode) != 6) { // not a 6-digit code
                if (strlen($authcode) != 10) {// also not a recovery code
                    throw Auth3Exception::invalidTwoFactor('length');
                } else { // using a recovery code, so validate it here
                    $usingRecovery = true;
                    $codeRepository = new \Auth3\Repositories\RecoveryCodeRepository();
                    if (!$codeRepository->validateCodeForUser($user->getIdentifier(), $authcode)) {
                        $logRepository->addEvent(new \Auth3\Entities\EventLogEntity('user', 'login-fail', $_SERVER['REMOTE_ADDR'] . ' provided invalid 2-factor recovery', $user->getIdentifier()));
                        $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));
                        throw Auth3Exception::invalidTwoFactor('verify');
                    } else {
                        $codeRepository->removeCodeForUser($user->getIdentifier(), $authcode);
                    }
                }
            }

            if (!$usingRecovery) {
                // check to see if authcode is valid if not using a recovery code
                $verify = \Auth3\Util\TwoFactor::verify($user->getGoogleAuthenticatorCode(), $authcode);
                if (!$verify) {
                    $logRepository->addEvent(new \Auth3\Entities\EventLogEntity('user', 'login-fail', $_SERVER['REMOTE_ADDR'] . ' provided invalid 2-factor code', $user->getIdentifier()));
                    $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));
                    throw Auth3Exception::invalidTwoFactor('verify');
                }
            }
            $logRepository->addEvent(new \Auth3\Entities\EventLogEntity('user', 'login', $_SERVER['REMOTE_ADDR'], $user->getIdentifier()));
            return $user;
        }

        $logRepository->addEvent(new \Auth3\Entities\EventLogEntity('user', 'login', $_SERVER['REMOTE_ADDR'], $user->getIdentifier()));
        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier() {
        return 'password';
    }
}
