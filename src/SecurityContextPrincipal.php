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
 * Implementation of a principal decorator that delegates to a security context.
 * 
 * @author Martin Schröder
 */
class SecurityContextPrincipal implements PrincipalInterface
{
	/**
	 * The principal being decorated.
	 * 
	 * @var SecurityContextInterface
	 */
	protected $context;
	
	/**
	 * Decorate the given principal.
	 * 
	 * @param SecurityContextInterface $context
	 */
	public function __construct(SecurityContextInterface $context)
	{
		$this->context = $context;
	}
	
	public function __debugInfo()
	{
		return [
			'principal' => $this->context->getPrincipal()	
		];
	}
	
	/**
	 * Get the security context being delegated to.
	 * 
	 * @return SecurityContextInterface
	 */
	public function getSecurityContext()
	{
		return $this->context;
	}
	
	public function getIdentity()
	{
		return $this->context->getPrincipal()->getIdentity();
	}
	
	public function getName()
	{
		return $this->context->getPrincipal()->getName();
	}
	
	public function isAnonymous()
	{
		return $this->context->getPrincipal()->isAnonymous();
	}
	
	public function isPrivileged()
	{
		return $this->context->getPrincipal()->isPrivileged();
	}
}
