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
use KoolKode\Http\Uri;
use KoolKode\Security\Authentication\FormAuthenticationProvider;
use KoolKode\Security\Authentication\Token\FormAuthToken;
use KoolKode\Security\Authentication\Token\TokenInterface;
use KoolKode\Security\SecurityException;
use KoolKode\Security\SecurityContextInterface;

/**
 * Enters a form-based authentication process.
 * 
 * @author Martin Schröder
 */
class FormAuth implements EntryPointInterface
{
	protected $auth;
	
	protected $securityContext;
	
	public function __construct(FormAuthenticationProvider $auth, SecurityContextInterface $context)
	{
		$this->auth = $auth;
		$this->securityContext = $context;
	}
	
	public function startAuthentication(TokenInterface $token, HttpRequest $request, HttpResponse $response)
	{
		if(!$token instanceof FormAuthToken)
		{
			throw new SecurityException(sprintf('Invalid token %s passed to %s', get_class($token), get_class($this)));
		}
		
		$loginUri = new Uri($this->auth->getLoginUri());
		
		$path = trim($request->getUri()->getPath(false), '/');
		$loginPath = trim($loginUri->getPath(false), '/');
		
		$session = $this->securityContext->getSession();
		$data = (array)$session->get($this->auth->getKey(), NULL);
		
		// Save the current URI when it is not the login URI.
		if($path !== $loginPath)
		{
			$data[FormAuthenticationProvider::SESSION_URI] = (string)$request->getUri();
			
			$session->set($this->auth->getKey(), $data);
		}
		
		$response->setStatus(Http::REDIRECT_TEMPORARY);
		$response->setReason(Http::getReason(Http::REDIRECT_TEMPORARY));
		$response->setHeader('Location', $loginUri);
	}
}
