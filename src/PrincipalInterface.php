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
 * Principals represent users / parties in the security system.
 * 
 * @author Martin Schröder
 */
interface PrincipalInterface
{	
	/**
	 * Get the unique identity of this principal (e.g. a username).
	 * 
	 * @return string
	 */
	public function getIdentity();
	
	/**
	 * Get display-ready name of this principal.
	 * 
	 * @return string
	 */
	public function getName();
	
	/**
	 * Check if this principal is anonymous.
	 * 
	 * @return boolean
	 */
	public function isAnonymous();

	/**
	 * Check if the principal is privileged, a privileged principal is usually able to
	 * bypass all security constraints.
	 * 
	 * @return boolean
	 */
	public function isPrivileged();
}
