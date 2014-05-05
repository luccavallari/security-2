<?php

/*
 * This file is part of KoolKode Security.
*
* (c) Martin Schröder <m.schroeder2007@gmail.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

namespace KoolKode\Security\Signature;

use KoolKode\Security\SecurityException;
use KoolKode\Security\SecurityUtil;

/**
 * Signs a message using an HMAC.
 * 
 * @author Martin Schröder
 */
class HmacSignatureProvider implements SignatureProviderInterface
{
	protected $secret;
	protected $algorithm;
	protected $iterations;
	
	public function __construct($secret, $algorithm = 'sha256', $iterations = 10)
	{
		$this->secret = (string)$secret;
		
		if(!in_array($algorithm, hash_algos(), true))
		{
			throw new \InvalidArgumentException(sprintf('Unsupported hash algorithm: "%s"', $algorithm));
		}
		
		$this->algorithm = (string)$algorithm;
		$this->iterations = (int)$iterations;
		
		if($this->iterations < 1)
		{
			$this->iterations = 1;
		}
		
		if($this->iterations > 10000)
		{
			$this->iterations = 10000;
		}
	}
	
	public function sign($message)
	{
		$hash = hash_hmac($this->algorithm, (string)$message, $this->secret, false);
		
		for($i = 1; $i < $this->iterations; $i++)
		{
			$hash ^= hash_hmac($this->algorithm, $hash, $this->secret, false);
		}
		
		return $hash . '|' . $message;
	}
	
	public function verify($message)
	{
		$parts = explode('|', $message);
		
		if(count($parts) != 2)
		{
			throw new SecurityException(sprintf('Given message does not contain an HMAC signature'));
		}
		
		if(!SecurityUtil::timingSafeEquals($this->sign($parts[1]), (string)$message))
		{
			throw new SecurityException(sprintf('HMAC verification failed'));
		}
		
		return (string)$parts[1];
	}
}
