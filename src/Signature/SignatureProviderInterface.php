<?php

/*
 * This file is part of KoolKode Security.
*
* (c) Martin Schröder <m.schroeder2007@gmail.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

namespace KoolKode\Security\Signature;

use KoolKode\Security\SecurityException;

/**
 * Provides capabilities to sign and verify arbitrary messages.
 * 
 * @author Martin Schröder
 */
interface SignatureProviderInterface
{
	/**
	 * Compute a signature and integrate it into the returned message.
	 * 
	 * @param string $message
	 * @return string
	 */
	public function sign($message);
	
	/**
	 * Verify the given signed message and return the message without signature.
	 * 
	 * @param string $message
	 * @return string
	 * 
	 * @throws SecurityException When an invalid message is passed or the signature is not valid.
	 */
	public function verify($message);
}
