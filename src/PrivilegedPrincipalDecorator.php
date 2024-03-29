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
 * Decorates another principal to enable privileged access.
 * 
 * @author Martin Schröder
 */
class PrivilegedPrincipalDecorator extends DelegatePrincipal
{
	public function isPrivileged()
	{
		return true;
	}
}
