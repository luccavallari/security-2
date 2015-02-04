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

use KoolKode\Http\Http;
use KoolKode\Http\HttpRequest;
use KoolKode\Http\HttpResponse;
use KoolKode\Http\Uri;
use KoolKode\Security\AnonymousPrincipal;
use KoolKode\Security\Authentication\EntryPoint\FormAuth;
use KoolKode\Security\Authentication\Token\FormAuthToken;
use KoolKode\Security\Authentication\Token\TokenInterface;
use KoolKode\Security\PrincipalProviderInterface;
use KoolKode\Security\SecurityContextInterface;
use KoolKode\Security\SecurityException;
use KoolKode\Util\RandomGeneratorInterface;

/**
 * @author Martin Schröder
 */
abstract class FormAuthenticationProvider extends AbstractAuthenticationProvider
{
	const FIELD_USERNAME = 'username';
	const FIELD_PASSWORD = 'password';
	const FIELD_GUARD = 'guard';
	
	const SESSION_GUARD = 'guard';
	const SESSION_IDENTITY = 'identity';
	const SESSION_URI = 'uri';
	
	protected $guard;
	
	protected $username;
	
	protected $failedLogin = false;
	
	protected $guardByteCount = 16;
	
	protected $guardStrength = RandomGeneratorInterface::STRENGTH_MEDIUM;
	
	public function getKey()
	{
		return str_replace('\\', '-', strtolower($this->getProviderName()));
	}
	
	public function getUsernameField()
	{
		return sprintf('auth[%s][%s]', $this->getKey(), self::FIELD_USERNAME);
	}
	
	public function getPasswordField()
	{
		return sprintf('auth[%s][%s]', $this->getKey(), self::FIELD_PASSWORD);
	}
	
	public function getGuardField()
	{
		return sprintf('auth[%s][%s]', $this->getKey(), self::FIELD_GUARD);
	}
	
	public function getGuard()
	{
		return $this->guard;
	}
	
	public function getUsername()
	{
		return $this->username;
	}
	
	public function isFailedLogin()
	{
		return $this->failedLogin;
	}
	
	public function setGuardByteCount($byteCount)
	{
		$this->guardByteCount = max(4, (int)$byteCount);
	}
	
	public function setGuardStrength($strength)
	{
		$this->guardStrength = max(RandomGeneratorInterface::STRENGTH_LOW, (int)$strength);
	}
	
	/**
	 * {@inheritdoc}
	 */
	protected function createEntryPoint(SecurityContextInterface $context)
	{
		return new FormAuth($this, $context);
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function getToken(SecurityContextInterface $context)
	{
		return new FormAuthToken($this, $context);
	}
	
	public abstract function getLoginUri();
	
	public abstract function getLogoutUri();
	
	/**
	 * {@inheritdoc}
	 */
	public function authenticate(SecurityContextInterface $context, TokenInterface $token, HttpRequest $request)
	{
		if(!$token instanceof FormAuthToken)
		{
			throw new SecurityException(sprintf('Token %s not supported by provider %s', get_class($token), get_class($this)));
		}
		
		$this->failedLogin = false;
		$this->username = $token->getUsername();
		$this->guard = $context->getRandomGenerator()->generateHexString($this->guardByteCount, $this->guardStrength);
		
		$path = trim($request->getUri()->getPath(false), '/');
		$loginPath = trim((new Uri($this->getLoginUri()))->getPath(false), '/');
		$logoutPath = trim((new Uri($this->getLogoutUri()))->getPath(false), '/');
		
		$isLogin = ($path === $loginPath);
		$isLogout = ($path === $logoutPath);
		
		$session = $context->getSession();
		
		if($isLogout)
		{
			$session->remove($this->getKey());
			
			$token->setPrincipal(new AnonymousPrincipal());
			$token->setStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
			
			return;
		}
		
		if($isLogin)
		{
			try
			{
				if($request->isPost(false))
				{
					$identity = $token->getUsername();
					$password = $token->getPassword();
					
					// Fetch user independent of guard in order to prevent leakage of timing information.
					$principal = $this->getPrincipalProvider()->findPrincipalUsingPassword($identity, $password);
					
					// Invalidate when guard fails.
					if(!$token->isGuarded())
					{
						$principal = NULL;
					}
					
					if($principal !== NULL)
					{
						$session = $context->getSession();
						$data = (array)$session->get($this->getKey(), NULL);
						
						$data[self::SESSION_IDENTITY] = (string)$principal->getIdentity();
						$session->set($this->getKey(), $data);
						
						if(array_key_exists(self::SESSION_URI, $data))
						{
							$uri = $data[self::SESSION_URI];
							
							unset($data[self::SESSION_URI]);
							$session->set($this->getKey(), $data);
							
							$response = new HttpResponse(Http::REDIRECT_TEMPORARY);
							$response->setHeader('Location', $uri);
								
							return $response;
						}
						
						$token->setPrincipal($principal);
						$token->setStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
						
						return;
					}
					
					$this->failedLogin = true;
				}
				
				$token->setPrincipal(new AnonymousPrincipal());
				$token->setStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
				
				return;
			}
			finally
			{
				$data = (array)$session->get($this->getKey(), []);
				$data[self::SESSION_GUARD] = $this->guard;
				
				$session->set($this->getKey(), $data);
			}
		}
	}
}
