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
 * Allows the security system to find security principals to be used in
 * the security context.
 * 
 * @author Martin Schröder
 */
interface PrincipalProviderInterface
{
	/**
	 * Find a principal by identity (does not involve any password checking!).
	 * 
	 * @param string $identity
	 * @return PrincipalInterface
	 */
	public function findPrincipal($identity);
	
	/**
	 * Find a principal by identity and cleartext password.
	 * 
	 * @param string $identity The identity of the principal.
	 * @param string $password The cleartext password of the principal.
	 * @return PrincipalInterface
	 */
	public function findPrincipalUsingPassword($identity, $password);
}
