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
use KoolKode\Security\Authentication\EntryPoint\NtlmAuth;
use KoolKode\Security\Authentication\Token\NtlmAuthToken;
use KoolKode\Security\Authentication\Token\TokenInterface;
use KoolKode\Security\SecurityContextInterface;
use KoolKode\Security\SecurityException;

abstract class NtlmAuthenticationProvider extends AbstractAuthenticationProvider
{
	public abstract function getDomain();
	
	protected function createEntryPoint(SecurityContextInterface $context)
	{
		return new NtlmAuth($this, $context);
	}
	
	public function getToken(SecurityContextInterface $context)
	{
		return new NtlmAuthToken($this, $context);
	}
	
	public function getLevelOfTrust()
	{
		return self::DEFAULT_LEVEL_OF_TRUST + 5;
	}
	
	public function createChallenge(SecurityContextInterface $context)
	{
		// FIXME: Need to create (and store!) a dynamic challenge... could use Session for storage.
		
		return '12345678';
		
		return $context->getRandomGenerator()->generateRaw(8);
	}
	
	public function authenticate(SecurityContextInterface $context, TokenInterface $token, HttpRequest $request)
	{
		if(!$token instanceof NtlmAuthToken)
		{
			throw new SecurityException(sprintf('Token %s not supported by provider %s', get_class($token), get_class($this)));
		}
		
		$provider = $this->getPrincipalProvider();
		
		$identity = $token->getUsername();
		$md4 = $provider->findPrincipalMD4($identity, $this->getDomain());
		$challenge = '12345678';
		
		if(!$token->isValidResponse($identity, $md4, $challenge))
		{
			$provider->notifyPrincipalNotFound($identity);
			$token->setStatus(TokenInterface::WRONG_CREDENTIALS);
				
			return;
		}
		
		$principal = $provider->findPrincipal($identity);
		
		if($principal === NULL)
		{
			$token->setStatus(TokenInterface::WRONG_CREDENTIALS);
				
			return;
		}
		
		$token->setPrincipal($principal);
		$token->setStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
		
		$provider->notifyPrinipalFound($principal);
	}
}
