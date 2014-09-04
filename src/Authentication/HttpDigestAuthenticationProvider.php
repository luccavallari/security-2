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
use KoolKode\Security\Authentication\EntryPoint\HttpDigest;
use KoolKode\Security\Authentication\Token\TokenInterface;
use KoolKode\Security\Authentication\Token\HttpDigestToken;
use KoolKode\Security\Authentication\Token\TokenInterface;
use KoolKode\Security\DigestPrincipalProviderInterface;
use KoolKode\Security\SecurityException;
use KoolKode\Security\SecurityContextInterface;
use KoolKode\Util\RandomGeneratorInterface;

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
	
	protected $nonceByteCount = 16;
	
	protected $nonceStrength = RandomGeneratorInterface::STRENGTH_LOW;
	
	protected $nonceTracker;
	
	/**
	 * Get the realm being used with HTTP authentication.
	 * 
	 * @return string
	 */
	public abstract function getRealm();
	
	/**
	 * {@inheritdoc}
	 */
	protected function createEntryPoint(SecurityContextInterface $context)
	{
		return new HttpDigest($this, $context);
	}
	
	/**
	 * {@inheritdoc}
	 */
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
	
	public function setNonceByteCount($count)
	{
		$this->nonceByteCount = max(4, (int)$count);
	}
	
	public function setNonceStrength($strength)
	{
		$this->nonceStrength = max(RandomGeneratorInterface::STRENGTH_LOW, (int)$strength);
	}
	
	/**
	 * @return NonceTrackerInterface
	 */
	public function getNonceTracker() { }
	
	/**
	 * Create a one-time nonce value (will generate a random nonce when no nonce tracker is being used).
	 * 
	 * @param SecurityContextInterface $context
	 * @return string
	 */
	public function createNonce(SecurityContextInterface $context)
	{
		if($this->nonceTracker === NULL)
		{
			return $context->getRandomGenerator()->generateHexString($this->nonceByteCount, $this->nonceStrength);
		}
		
		$this->nonceTracker->initializeTracker();
		
		return $this->nonceTracker->createNonce();
	}
	
	/**
	 * {@inheritdoc}
	 */
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
	
	/**
	 * {@inheritdoc}
	 */
	public function processResponse(SecurityContextInterface $context, TokenInterface $token, HttpRequest $request, HttpResponse $response)
	{
		if(!$token instanceof HttpDigestToken)
		{
			throw new SecurityException(sprintf('Token %s not supported by provider %s', get_class($token), get_class($this)));
		}
		
		if($token->getStatus() == TokenInterface::AUTHENTICATION_SUCCESSFUL)
		{
			$response->addHeader('Authentication-Info', sprintf(
				'nextnonce="%s", qop=%s',
				$token->getNonce(),
				$token->getQualityOfProtection()
			));
		}
	}
}
