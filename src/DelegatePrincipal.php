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
	
	/**
	 * {@inheritdoc}
	 */
	public function getIdentity()
	{
		return $this->principal->getIdentity();
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function getName()
	{
		return $this->principal->getName();
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function getAggregatedPrincipals()
	{
		$aggregate = $this->principal->getAggregatedPrincipals();
		
		if(false !== ($index = array_search($this->principal, $aggregate, true)))
		{
			unset($aggregate[$index]);
		}
		
		return array_merge([$this], $aggregate);
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function isAnonymous()
	{
		return $this->principal->isAnonymous();
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function isPrivileged()
	{
		return $this->principal->isPrivileged();
	}
}
