<?php

/*
 * This file is part of KoolKode Security.
*
* (c) Martin Schröder <m.schroeder2007@gmail.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

namespace KoolKode\Security\Firewall;

use KoolKode\Http\Http;
use KoolKode\Http\HttpRequest;
use KoolKode\Http\HttpResponse;
use KoolKode\Security\AccessDeniedException;
use KoolKode\Security\Authentication\AuthenticationProviderInterface;
use KoolKode\Security\Authentication\Token\TokenInterface;
use KoolKode\Security\MutableSecurityContextInterface;

abstract class AbstractFirewall implements FirewallInterface
{
	protected $auth = self::AUTH_ONE;
	
	protected $eagerAuth = true;
	
	protected $requestMatchers = [];
	
	protected $authenticationProviders = [];
	
	protected $requestInterceptors;
	
	protected $responseInterceptors;
	
	/**
	 * Holds all authentication tokens that have been prepared for this request indexed
	 * by authentication provider names.
	 *
	 * @var array<integer, TokenInterface>
	 */
	protected $tokens = [];
	
	/**
	 * Holds all authenticated tokens indexed by provider name.
	 *
	 * @var array<integer, TokenInterface>
	 */
	protected $authenticatedTokens = [];
	
	protected $securityContext;
	
	public function __construct(MutableSecurityContextInterface $context)
	{
		$this->securityContext = $context;
		
		$this->requestInterceptors = new \SplPriorityQueue();
		$this->responseInterceptors = new \SplPriorityQueue();
		
		$this->initialize();
	}
	
	/**
	 * Custom initializer called after object construction.
	 */
	protected function initialize() { }
	
	public function setAuthMode($auth)
	{
		switch($auth)
		{
			case self::AUTH_ALL:
			case self::AUTH_AT_LEAST_ONE:
			case self::AUTH_ONE:
				$this->auth = (int)$auth;
				break;
			default:
				throw new \InvalidArgumentException(sprintf('Unsupported firewall auth mode: "%s"', $auth));
		}
	}
	
	public function setEager($eager)
	{
		$this->eagerAuth = $eager ? true : false;
	}
	
	public function registerAuthenticationProvider(AuthenticationProviderInterface $provider)
	{
		$level = $provider->getLevelOfTrust();
		
		for($size = count($this->authenticationProviders), $i = 0; $i < $size; $i++)
		{
			if($this->authenticationProviders[$i]->getLevelOfTrust() < $level)
			{
				array_splice($this->authenticationProviders, $i, 0, [$provider]);
				
				return;
			}
		}
		
		$this->authenticationProviders[] = $provider;
	}
	
	public function matchesRequest(HttpRequest $request)
	{
		if(empty($this->requestMatchers))
		{
			return true;
		}
		
		foreach($this->requestMatchers as $matcher)
		{
			if($matcher->matchesRequest($request))
			{
				return true;
			}
		}
		
		return false;
	}
	
	public function registerRequestMatcher(RequestMatcherInterface $matcher)
	{
		$this->requestMatchers[] = $matcher;
	}
	
	public function interceptRequest(HttpRequest $request)
	{
		$this->tokens = [];
		$this->authenticatedTokens = [];
		
		foreach(clone $this->requestInterceptors as $interceptor)
		{
			$response = $interceptor->interceptRequest($request);
			
			if($response instanceof HttpResponse)
			{
				return $response;
			}
		}
		
		foreach($this->authenticationProviders as $i => $provider)
		{
			if(!$provider->matchesRequest($request))
			{
				continue;
			}
			
			$response = $provider->interceptRequest($this->securityContext, $request);
			
			if($response instanceof HttpResponse)
			{
				return $response;
			}
				
			$token = $provider->getToken($this->securityContext);
			$token->updateCredentials($request);
				
			$this->tokens[$i] = $token;
		}
		
		// Authenticate all tokens that need auth.
		foreach($this->tokens as $i => $token)
		{
			$provider = $this->authenticationProviders[$i];
			
			if($token->getStatus() == TokenInterface::AUTHENTICATION_NEEDED)
			{
				$response = $provider->authenticate($this->securityContext, $token, $request);
		
				if($response instanceof HttpResponse)
				{
					return $response;
				}
			}
				
			if($token->getStatus() == TokenInterface::AUTHENTICATION_SUCCESSFUL)
			{
				$this->authenticatedTokens[$i] = $token;
				
				if($this->auth == self::AUTH_ONE)
				{
					$this->securityContext->setPrincipal($token->getPrincipal());
					
					return;
				}
			}
		}
		
		$authenticated = count($this->authenticatedTokens);
		$all = count($this->tokens);
		$needAuth = $this->eagerAuth;
		
		if($this->auth === self::AUTH_ALL && $authenticated === $all)
		{
			$needAuth = false;
		}
		
		if($this->auth === self::AUTH_AT_LEAST_ONE && !empty($authenticated))
		{
			$needAuth = false;
		}
		
		if($needAuth)
		{
			return $this->authenticate($request);
		}
		
		foreach($this->authenticatedTokens as $token)
		{
			$this->securityContext->setPrincipal($token->getPrinicpal());
			
			break;
		}
	}
	
	public function registerRequestInterceptor(RequestInterceptorInterface $interceptor)
	{
		$this->requestInterceptors->insert($interceptor, $interceptor->getRequestInterceptorPriority());
	}
	
	public function interceptResponse(HttpRequest $request, HttpResponse $response)
	{
		foreach($this->authenticatedTokens as $i => $token)
		{
			$this->authenticationProviders[$i]->processResponse($this->securityContext, $token, $request, $response);
		}
		
		foreach(clone $this->responseInterceptors as $interceptor)
		{
			$response = $interceptor->interceptResponse($request, $response);
		}
		
		return $response;
	}
	
	public function registerResponseInterceptor(ResponseInterceptorInterface $interceptor)
	{
		$this->responseInterceptors->insert($interceptor, $interceptor->getResponseInterceptorPriority());
	}
	
	public function isAuthenticated()
	{
		switch($this->auth)
		{
			case self::AUTH_ALL:
				return count($this->tokens) === count($this->authenticatedTokens);
			case self::AUTH_AT_LEAST_ONE:
			case self::AUTH_ONE:
				return !empty($this->authenticatedTokens);
		}
	}
	
	public function authenticate(HttpRequest $request)
	{
		$entryPoints = [];
			
		foreach($this->tokens as $i => $token)
		{
			if($token->getStatus() != TokenInterface::AUTHENTICATION_SUCCESSFUL)
			{
				$entryPoints[$i] = $this->authenticationProviders[$i]->getEntryPoint($this->securityContext);
					
			}
		}
			
		if(empty($entryPoints))
		{
			throw new AccessDeniedException('Authentication failed');
		}
			
		$response = new HttpResponse(Http::CODE_UNAUTHORIZED);
			
		foreach($entryPoints as $i => $entryPoint)
		{
			$entryPoint->startAuthentication($this->tokens[$i], $request, $response);
		}
			
		return $response;
	}
}
