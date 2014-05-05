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
	protected $privileged;
	
	public function __construct($identity, $name, $privileged = false)
	{
		$this->identity = (string)$identity;
		$this->name = (string)$name;
		$this->privileged = $privileged ? true : false;
	}
	
	public function getIdentity()
	{
		return $this->identity;
	}
	
	public function getName()
	{
		return $this->name;
	}
	
	public function isAnonymous()
	{
		return false;
	}
	
	public function isPrivileged()
	{
		return $this->privileged;
	}
}
