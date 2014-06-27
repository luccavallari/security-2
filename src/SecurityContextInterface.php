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

use KoolKode\Session\SessionInterface;
use KoolKode\Util\RandomGenerator;

/**
 * Provides covenient access to components of the security system.
 * 
 * @author Martin Schröder
 */
interface SecurityContextInterface
{
	/**
	 * Get the active session (may change per request, do not store a reference to
	 * the session).
	 * 
	 * @return SessionInterface
	 */
	public function getSession();
	
	/**
	 * Get the currently authenticated principal.
	 * 
	 * @return PrincipalInterface
	 */
	public function getPrincipal();
	
	/**
	 * Get a random generator to be used in creating nonces etc.
	 * 
	 * @return RandomGenerator
	 */
	public function getRandomGenerator();
}
