<?php

/*
 * This file is part of KoolKode Security.
*
* (c) Martin Schröder <m.schroeder2007@gmail.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

namespace KoolKode\Security\Authentication;

use KoolKode\Http\HttpRequest;
use KoolKode\Http\HttpResponse;
use KoolKode\Security\Authentication\EntryPoint\EntryPointInterface;
use KoolKode\Security\Authentication\Token\TokenInterface;
use KoolKode\Security\SecurityContextInterface;

/**
 * Contract for a pluggable authentication provider.
 * 
 * @author Martin Schröder
 */
interface AuthenticationProviderInterface
{
	/**
	 * Default level of trust for authentication providers.
	 * 
	 * @var integer
	 */
	const DEFAULT_LEVEL_OF_TRUST = 1;
	
	/**
	 * Get the unique name of this authentication provider.
	 * 
	 * @return string
	 */
	public function getProviderName();

	/**
	 * Get the level of trust for this authentication provider, providers with a higher
	 * level of trust are invoked before providers with a lower level of trust.
	 * 
	 * @return integer
	 */
	public function getLevelOfTrust();
	
	/**
	 * Check if the auth provider is enabled for the given request.
	 * 
	 * @param HttpRequest $request
	 * @return true
	 */
	public function matchesRequest(HttpRequest $request);

	/**
	 * Get the authentication token used by this authentication provider.
	 * 
	 * @param SecurityContextInterface $context
	 * @return TokenInterface
	 */
	public function getToken(SecurityContextInterface $context);
	
	/**
	 * Get the authentication entry point used by this authentication provider.
	 * 
	 * @param SecurityContextInterface $context
	 * @return EntryPointInterface
	 */
	public function getEntryPoint(SecurityContextInterface $context);
	
	/**
	 * Intercept a matched request, allows to modify the request or return an HTTP response.
	 * 
	 * @param SecurityContextInterface $context
	 * @param HttpRequest $request
	 * @return HttpResponse or NULL if the request is not being intercepted.
	 * 
	 * @deprecated
	 */
	public function interceptRequest(SecurityContextInterface $context, HttpRequest $request);
	
	/**
	 * Post-process an HTTP response as needed.
	 * 
	 * @param SecurityContextInterface $context
	 * @param TokenInterface $token
	 * @param HttpRequest $request
	 * @param HttpResponse $response
	 */
	public function processResponse(SecurityContextInterface $context, TokenInterface $token, HttpRequest $request, HttpResponse $response);

	/**
	 * Try to authenticate the given token.
	 * 
	 * @param SecurityContextInterface $context
	 * @param TokenInterface $token
	 * @param HttpRequest $request
	 */
	public function authenticate(SecurityContextInterface $context, TokenInterface $token, HttpRequest $request);
}
