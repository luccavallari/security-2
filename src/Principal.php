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
 * Generic implementation of a security principal.
 * 
 * @author Martin Schröder
 */
class Principal implements PrincipalInterface
{
	protected $identity;
	
	protected $name;
	
	protected $aggregatedPrincipals = [];
	
	protected $privileged;
	
	public function __construct($identity, $name, array $aggregatedPrincipals = [], $privileged = false)
	{
		$this->identity = (string)$identity;
		$this->name = (string)$name;
		$this->aggregatedPrincipals = $aggregatedPrincipals;
		$this->privileged = $privileged ? true : false;
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function getIdentity()
	{
		return $this->identity;
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function getName()
	{
		return $this->name;
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function getAggregatedPrincipals()
	{
		$principals = [$this->identity => $this];
		
		foreach($this->aggregatedPrincipals as $aggregate)
		{
			foreach($aggregate->getAggregatedPrincipals() as $principal)
			{
				$principals[$principal->getIdentity()] = $principal;
			}
		}
		
		return array_values($principals);
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function isAnonymous()
	{
		return false;
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function isPrivileged()
	{
		return $this->privileged;
	}
}
