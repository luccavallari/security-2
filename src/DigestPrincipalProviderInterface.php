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
 * Extended principal provider that can be used with HTTP digest authentication. 
 * 
 * @author Martin Schröder
 */
interface DigestPrincipalProviderInterface extends PrincipalProviderInterface
{
	/**
	 * Find the HA1 hash part used by HTTP digest authentication for the given identity and realm.
	 * 
	 * <b>HA1 := MD5(identity ":" realm ":" password)</b>
	 * 
	 * @param string $identity The identity of the principal.
	 * @param string $realm Realm being used by HTTP auth.
	 * @return string HA1 hash part to be used in HTTP digest authentication or false.
	 */
	public function findPrincipalHA1($identity, $realm);
	
	/**
	 * Notify the provider that the principal has been found by HA1.
	 * 
	 * @param PrincipalInterface $principal
	 */
	public function notifyPrinipalFound(PrincipalInterface $principal);
	
	/**
	 * Notify the provider when a principal was not found by HA1.
	 *
	 * @param string $identity
	 */
	public function notifyPrincipalNotFound($identity);
}
