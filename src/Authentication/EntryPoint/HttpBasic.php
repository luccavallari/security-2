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
use KoolKode\Security\Authentication\HttpBasicAuthenticationProvider;
use KoolKode\Security\Authentication\Token\HttpBasicToken;
use KoolKode\Security\Authentication\Token\TokenInterface;
use KoolKode\Security\SecurityException;
use KoolKode\Security\SecurityContextInterface;

/**
 * Entry point for HTTP basic authentication, very simple authentication mechanism that transmits
 * data in cleartext. Clients may encrypt credentials before sending them to avoid this problem.
 * 
 * @author Martin Schröder
 */
class HttpBasic implements EntryPointInterface
{
	protected $auth;
	protected $securityContext;
	
	public function __construct(HttpBasicAuthenticationProvider $auth, SecurityContextInterface $context)
	{
		$this->auth = $auth;
		$this->securityContext = $context;
	}
	
	public function startAuthentication(TokenInterface $token, HttpRequest $request, HttpResponse $response)
	{
		if(!$token instanceof HttpBasicToken)
		{
			throw new SecurityException(sprintf('Invalid token %s passed to %s', get_class($token), get_class($this)));
		}
		
		$response->setStatus(Http::CODE_UNAUTHORIZED);
		$response->setReason(Http::getReason(Http::CODE_UNAUTHORIZED));
		
		$response->addHeader('WWW-Authenticate', sprintf('Basic realm="%s"', $this->auth->getRealm()));
	}
}
