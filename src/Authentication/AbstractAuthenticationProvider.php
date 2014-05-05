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
use KoolKode\Security\SecurityContextInterface;

/**
 * @author Martin Schröder
 */
abstract class AbstractAuthenticationProvider implements AuthenticationProviderInterface
{
	private $entryPoint;
	
	private $requestInterceptors = [];
		
	public function getProviderName()
	{
		return get_class($this);
	}
	
	public function getLevelOfTrust()
	{
		return self::DEFAULT_LEVEL_OF_TRUST;
	}
	
	public function matchesRequest(HttpRequest $request)
	{
		return true;
	}
	
	public abstract function getPrincipalProvider();
	
	public function getEntryPoint(SecurityContextInterface $context)
	{
		if($this->entryPoint === NULL)
		{
			$this->entryPoint = $this->createEntryPoint($context);
		}
		
		return $this->entryPoint;
	}
	
	protected abstract function createEntryPoint(SecurityContextInterface $context);
	
	public function addRequestInterceptor(callable $interceptor)
	{
		$this->requestInterceptors[] = $interceptor;
	}
	
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
	
	public function processResponse(SecurityContextInterface $context, HttpRequest $request, HttpResponse $response) { }
}
