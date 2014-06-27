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
 * @author Martin Schröder
 */
abstract class SecurityUtil
{
	/**
	 * Perform a timing-safe string comparison.
	 * 
	 * @param string $safe Safe string value.
	 * @param string $user User-supplied value for comparsion.
	 * @return boolean
	 */
	public static function timingSafeEquals($safe, $user)
	{
		$safe .= chr(0);
		$user .= chr(0);

		$safeLen = strlen($safe);
		$userLen = strlen($user);
		$result = $safeLen - $userLen;

		for($i = 0; $i < $userLen; $i++)
		{
			$result |= (ord($safe[$i % $safeLen]) ^ ord($user[$i]));
		}

		return $result === 0;
	}
}
