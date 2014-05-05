<?php

/*
 * This file is part of KoolKode Security.
*
* (c) Martin Schröder <m.schroeder2007@gmail.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

namespace KoolKode\Security;

/**
 * Simple principal provider to be used in unit tests.
 * 
 * @author Martin Schröder
 */
class TestPrincipalProvider implements DigestPrincipalProviderInterface
{
	protected $principals = [];
	
	/**
	 * Register a new principal to be provided to the security system.
	 * 
	 * @param TestPrincipal $principal
	 */
	public function registerPrincipal(TestPrincipal $principal)
	{
		$this->principals[$principal->getIdentity()] = $principal;
	}
	
	public function findPrincipal($identity)
	{
		foreach($this->principals as $principal)
		{
			if($principal->getIdentity() === $identity)
			{
				return $principal;
			}
		}
	}
	
	public function findPrincipalUsingPassword($identity, $password)
	{
		foreach($this->principals as $principal)
		{
			if($principal->getIdentity() === $identity && $principal->getPassword() === $password)
			{
				return $principal;
			}
		}
	}
	
	public function findPrincipalHA1($identity, $realm)
	{
		foreach($this->principals as $principal)
		{
			if($principal->getIdentity() === $identity)
			{
				return md5(sprintf('%s:%s:%s', $principal->getIdentity(), $realm, $principal->getPassword()));
			}
		}
	}
	
	public function notifyPrinipalFound(PrincipalInterface $principal) { }
	
	public function notifyPrincipalNotFound($identity) { }
}
