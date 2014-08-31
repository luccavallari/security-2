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
use KoolKode\Security\Authentication\EntryPoint\HttpBasic;
use KoolKode\Security\Authentication\Token\HttpBasicToken;
use KoolKode\Security\Authentication\Token\TokenInterface;
use KoolKode\Security\PrincipalProviderInterface;
use KoolKode\Security\SecurityException;
use KoolKode\Security\SecurityContextInterface;

/**
 * @author Martin Schröder
 */
abstract class HttpBasicAuthenticationProvider extends AbstractAuthenticationProvider
{
	/**
	 * {@inheritdoc}
	 */
	protected function createEntryPoint(SecurityContextInterface $context)
	{
		return new HttpBasic($this, $context);
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function getToken(SecurityContextInterface $context)
	{
		return new HttpBasicToken($this, $context);
	}
	
	/**
	 * Get the realm being used with HTTP auuthentication.
	 * 
	 * @return string
	 */
	public abstract function getRealm();
	
	/**
	 * {@inheritdoc}
	 */
	public function authenticate(SecurityContextInterface $context, TokenInterface $token, HttpRequest $request)
	{
		if(!$token instanceof HttpBasicToken)
		{
			throw new SecurityException(sprintf('Token %s not supported by provider %s', get_class($token), get_class($this)));
		}
		
		$identity = $token->getUsername();
		$password = $token->getPassword();
		
		$principal = $this->getPrincipalProvider()->findPrincipalUsingPassword($identity, $password);
		
		if($principal === NULL)
		{
			$token->setStatus(TokenInterface::WRONG_CREDENTIALS);
			
			return;
		}
		
		$token->setPrincipal($principal);
		$token->setStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
	}
}
