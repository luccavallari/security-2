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
 * Implementation of a principal decorator that does not provide additional functionality, can be
 * sub-classed in order to easily implement custom decorators.
 * 
 * @author Martin Schröder
 */
class DelegatePrincipal implements PrincipalInterface
{
	/**
	 * The principal being decorated.
	 * 
	 * @var PrincipalInterface
	 */
	protected $principal;
	
	/**
	 * Decorate the given principal.
	 * 
	 * @param PrincipalInterface $principal
	 */
	public function __construct(PrincipalInterface $principal)
	{
		$this->principal = $principal;
	}
	
	/**
	 * Get the principal being decorated.
	 * 
	 * @return PrincipalInterface
	 */
	public function getPrincipal()
	{
		return $this->principal;
	}
	
	public function getIdentity()
	{
		return $this->principal->getIdentity();
	}
	
	public function getName()
	{
		return $this->principal->getName();
	}
	
	public function isAnonymous()
	{
		return $this->principal->isAnonymous();
	}
	
	public function isPrivileged()
	{
		return $this->principal->isPrivileged();
	}
}
