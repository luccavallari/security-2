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
use KoolKode\Security\Authentication\EntryPoint\HttpDigest;
use KoolKode\Security\Authentication\Token\HttpDigestToken;
use KoolKode\Security\Authentication\Token\TokenInterface;
use KoolKode\Security\DigestPrincipalProviderInterface;
use KoolKode\Security\RandomGenerator;
use KoolKode\Security\SecurityException;
use KoolKode\Security\SecurityContextInterface;

/**
 * @author Martin Schröder
 */
abstract class HttpDigestAuthenticationProvider extends AbstractAuthenticationProvider
{
	/**
	 * HTTP Digest Authentication as specified in RFC 2617.
	 *
	 * @link http://tools.ietf.org/html/rfc2617
	 * @var string
	 */
	const QOP_AUTH = 'auth';
	
	/**
	 * Basically the same as QOP_AUTH but includes an MD5 hash of the request
	 * body into the response hash (many clients do not support this).
	 *
	 * @var string
	 */
	const QOP_AUTH_INT = 'auth-int';
	
	protected $qop = self::QOP_AUTH;
	
	protected $random;
	
	protected $nonceTracker;
	
	public abstract function getRealm();
	
	protected function createEntryPoint(SecurityContextInterface $context)
	{
		return new HttpDigest($this, $context);
	}
	
	public function getToken(SecurityContextInterface $context)
	{
		return new HttpDigestToken($this, $context);
	}
	
	public function getOpaque()
	{
		return md5($this->getRealm());
	}
	
	public function getQualityOfProtection()
	{
		return $this->qop;
	}
	
	public function setQualityOfProtection($qop)
	{
		switch($qop)
		{
			case self::QOP_AUTH:
			case self::QOP_AUTH_INT:
				$this->qop = $qop;
			break;
			default:
				throw new SecurityException('Unsupported quality of protection: ' . $qop);
		}
	}
	
	public function getNonceTracker() { }
	
	public function createNonce()
	{
		if($this->nonceTracker === NULL)
		{
			if($this->random === NULL)
			{
				$this->random = new RandomGenerator();
			}
			
			return bin2hex($this->random->generateRandom(18));
		}
		
		$this->nonceTracker->initializeTracker();
		
		return $this->nonceTracker->createNonce();
	}
	
	public function authenticate(SecurityContextInterface $context, TokenInterface $token, HttpRequest $request)
	{
		if(!$token instanceof HttpDigestToken)
		{
			throw new SecurityException(sprintf('Token %s not supported by provider %s', get_class($token), get_class($this)));
		}
		
		if($this->nonceTracker !== NULL)
		{
			$this->nonceTracker->initializeTracker();
			
			switch($this->nonceTracker->checkNonce($token->getNonce(), $token->getNonceCount()))
			{
				case NonceTrackerInterface::NONCE_OK:
					// Nonce is OK...
				break;
				case NonceTrackerInterface::NONCE_STALE:
					$token->setStale(true);
					return;
				default:
					return;
			}
		}
		
		$provider = $this->getPrincipalProvider();
		
		$identity = $token->getUsername();
		$ha1 = $provider->findPrincipalHA1($identity, $this->getRealm());
		
		if(!$token->isValidResponse($ha1))
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
