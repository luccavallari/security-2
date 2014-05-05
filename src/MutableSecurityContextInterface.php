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

/**
 * @author Martin Schröder
 */
interface MutableSecurityContextInterface extends SecurityContextInterface
{
	public function setPrincipal(PrincipalInterface $principal);
	
	public function setSession(SessionInterface $session);
	
	public function removeSession();
}
