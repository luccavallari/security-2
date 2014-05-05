<?php

/*
 * This file is part of KoolKode Security.
*
* (c) Martin Schröder <m.schroeder2007@gmail.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

namespace KoolKode\Security\Authentication;

/**
 * Nonce tracker can be used by HTTP digest authentication to prevent replay attacks.
 * 
 * @author Martin Schröder
 */
interface NonceTrackerInterface
{
	/**
	 * Nonce is OK.
	 * 
	 * @var integer
	 */
	const NONCE_OK = 1;

	/**
	 * Nonce would be OK but has expired due to restricted lifetime.
	 * 
	 * @var integer
	 */
	const NONCE_STALE = 2;
	
	/**
	 * Nonce is invalid.
	 * 
	 * @var integer
	 */
	const NONCE_INVALID = 3;
	
	/**
	 * Initializes the tracker before it is used.
	 */
	public function initializeTracker();
	
	/**
	 * Create a tracked nonce value to be used in authentication.
	 * 
	 * @return string
	 */
	public function createNonce();
	
	/**
	 * Check the given nonce for existence and expiration.
	 * 
	 * @param string $nonce Nonce as sent by client.
	 * @param integer $count Nonce count sent by client (converted from hex-string to integer).
	 * @return integer State of the nonce, one of the NONCE_* constants.
	 */
	public function checkNonce($nonce, $count);
}
