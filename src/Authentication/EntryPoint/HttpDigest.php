<?php

/*
 * This file is part of KoolKode Security.
*
* (c) Martin Schröder <m.schroeder2007@gmail.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

namespace KoolKode\Security\Authentication\EntryPoint;

use KoolKode\Http\Http;
use KoolKode\Http\HttpRequest;
use KoolKode\Http\HttpResponse;
use KoolKode\Security\Authentication\HttpDigestAuthenticationProvider;
use KoolKode\Security\Authentication\Token\HttpDigestToken;
use KoolKode\Security\Authentication\Token\TokenInterface;
use KoolKode\Security\SecurityException;
use KoolKode\Security\SecurityContextInterface;

/**
 * Entry point for HTTP Digest Authentication. Provides some security enhancements compared
 * to HTTP Basic Authentication, user passwords are never transmitted in cleartext.
 * 
 * @author Martin Schröder
 */
class HttpDigest implements EntryPointInterface
{
	protected $auth;
	protected $securityContext;
	
	public function __construct(HttpDigestAuthenticationProvider $auth, SecurityContextInterface $context)
	{
		$this->auth = $auth;
		$this->securityContext = $context;
	}
	
	public function startAuthentication(TokenInterface $token, HttpRequest $request, HttpResponse $response)
	{
		if(!$token instanceof HttpDigestToken)
		{
			throw new SecurityException(sprintf('Invalid token %s passed to %s', get_class($token), get_class($this)));
		}
		
		$params = [
			'realm' => $this->auth->getRealm(),
			'qop' => $this->auth->getQualityOfProtection(),
			'opaque' => $this->auth->getOpaque(),
			'nonce' => $this->auth->createNonce($this->securityContext),
		];
		
		if($token->isStale())
		{
			$params['stale'] = true;
		}
		
		$authString = 'Digest ';
		$i = 0;
		
		foreach($params as $name => $value)
		{
			if($i++ > 0)
			{
				$authString .= ',';
			}
			
			if(is_bool($value))
			{
				$authString .= sprintf('%s=%s', $name, $value ? 'true' : 'false');
			}
			elseif(is_numeric($value))
			{
				$authString .= sprintf('%s=%s', $name, $value);
			}
			else
			{
				$authString .= sprintf('%s="%s"', $name, str_replace('"', '\\"', trim($value)));
			}
		}
		
		$response->setStatus(Http::CODE_UNAUTHORIZED);
		$response->setReason(Http::getReason(Http::CODE_UNAUTHORIZED));
		
		$response->addHeader('WWW-Authenticate', $authString);
	}
}
