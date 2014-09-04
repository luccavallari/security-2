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
use KoolKode\Security\PrincipalProviderInterface;
use KoolKode\Security\SecurityContextInterface;

/**
 * @author Martin Schröder
 */
abstract class AbstractAuthenticationProvider implements AuthenticationProviderInterface
{
	private $entryPoint;
	
	private $requestInterceptors = [];
	
	/**
	 * {@inheritdoc}
	 */
	public function getProviderName()
	{
		return get_class($this);
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function getLevelOfTrust()
	{
		return self::DEFAULT_LEVEL_OF_TRUST;
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function matchesRequest(HttpRequest $request)
	{
		return true;
	}
	
	/**
	 * Get the principal provider used by the authentication provider.
	 * 
	 * @return PrincipalProviderInterface
	 */
	public abstract function getPrincipalProvider();
	
	/**
	 * {@inheritdoc}
	 */
	public function getEntryPoint(SecurityContextInterface $context)
	{
		if($this->entryPoint === NULL)
		{
			$this->entryPoint = $this->createEntryPoint($context);
		}
		
		return $this->entryPoint;
	}
	
	/**
	 * Create the entry point required by this auth provider.
	 * 
	 * @param SecurityContextInterface $context
	 * @return EntryPointInterface
	 */
	protected abstract function createEntryPoint(SecurityContextInterface $context);
	
	public function addRequestInterceptor(callable $interceptor)
	{
		$this->requestInterceptors[] = $interceptor;
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function interceptRequest(SecurityContextInterface $context, HttpRequest $request)
	{
		foreach($this->requestInterceptors as $interceptor)
		{
			if($response = $interceptor($request))
			{
				return $response;
			}
		}
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function processResponse(SecurityContextInterface $context, TokenInterface $token, HttpRequest $request, HttpResponse $response) { }
}
