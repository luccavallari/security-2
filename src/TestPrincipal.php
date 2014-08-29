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
 * Simple principal implementation to be used in unit tests.
 * 
 * @author Martin Schröder
 */
class TestPrincipal extends Principal
{
	protected $password;
	
	public function __construct($identity, $password, $name, array $aggregatedPrincipals = [], $privileged = false)
	{
		parent::__construct($identity, $name, $aggregatedPrincipals, $privileged);
		
		$this->password = (string)$password;
	}
	
	public function getPassword()
	{
		return $this->password;
	}
}
