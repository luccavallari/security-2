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
 * Extended principal provider that can be used with NTLM HTTP authentication. 
 * 
 * @author Martin Schröder
 */
interface NtlmPrincipalProviderInterface extends DigestPrincipalProviderInterface
{
	/**
	 * Find the MD4 hash of the password of the given identity / principal.
	 * 
	 * <b>MD4 := md4(utf8_to_utf16le(password))</b>
	 * 
	 * The user's password needs to be UTF-16 encoded (in little endian byte order).
	 * 
	 * In PHP <code>hash('md4', iconv('UTF-8', 'UTF-16LE', $password), true)</code> does the trick.
	 * 
	 * @param string $identity The identity of the principal.
	 * @param string $domain The domain of the server that requires the user to authenticate.
	 * @return string MD4 hash of the user's password or false.
	 */
	public function findPrincipalMD4($identity, $domain);
}
