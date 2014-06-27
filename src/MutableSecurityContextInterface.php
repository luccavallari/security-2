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
interface MutableSecurityContextInterface extends SecurityContextInterface
{
	public function setPrincipal(PrincipalInterface $principal);
}
