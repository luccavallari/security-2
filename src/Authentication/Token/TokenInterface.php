<?php

/*
 * This file is part of KoolKode Security.
*
* (c) Martin Schröder <m.schroeder2007@gmail.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

namespace KoolKode\Security\Authentication\Token;

use KoolKode\Http\HttpRequest;
use KoolKode\Security\PrincipalInterface;

/**
 * Every authentication provider uses a token to keep track of authentication details.
 * 
 * @author Martin Schröder
 */
interface TokenInterface
{
	/**
	 * Status: No credentials have been passed to the application.
	 * 
	 * @var integer
	 */
	const NO_CREDENTIALS = 1;
	
	/**
	 * Status: Credentials have been passed to the application and an authentication provider
	 * must determine a security principal for these credentials.
	 *
	 * @var integer
	 */
	const AUTHENTICATION_NEEDED = 2;
	
	/**
	 * Status: Credentials have been passed to the application however no security principal
	 * was found for these credentials.
	 * 
	 * @var integer
	 */
	const WRONG_CREDENTIALS = 3;
	
	/**
	 * Status: A security principal has been authenticated successfully using the given credentials.
	 * 
	 * @var integer
	 */
	const AUTHENTICATION_SUCCESSFUL = 4;
	
	/**
	 * Get the authentication status of this token, one of the AUTHENTICATION_* constants.
	 * 
	 * @return integer
	 */
	public function getStatus();
	
	/**
	 * Set the authentication status, one of the AUTHENTICATION_* constants.
	 * 
	 * @param integer $status
	 */
	public function setStatus($status);
	
	/**
	 * Get the principal that has been authenticated by this token.
	 * 
	 * @return PrincipalInterface
	 */
	public function getPrincipal();
	
	/**
	 * Set the principal that has been authenticated by this token.
	 * 
	 * @param PrincipalInterface $principal
	 */
	public function setPrincipal(PrincipalInterface $principal);

	/**
	 * Update credentials using the given HTTP request.
	 * 
	 * @param HttpRequest $request
	 */
	public function updateCredentials(HttpRequest $request);
}
