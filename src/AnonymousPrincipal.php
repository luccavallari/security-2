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
 * Implementation of an anonymous principal that does not have access to any protected resource.
 * 
 * @author Martin Schröder
 */
class AnonymousPrincipal implements PrincipalInterface
{
	public function getIdentity()
	{
		return '';
	}
	
	public function getName()
	{
		return '';
	}
	
	public function isAnonymous()
	{
		return true;
	}
	
	public function isPrivileged()
	{
		return false;
	}
}
