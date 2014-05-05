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

use KoolKode\Security\PrincipalInterface;

/**
 * @author Martin Schröder
 */
abstract class AbstractToken implements TokenInterface
{
	protected $status = self::NO_CREDENTIALS;
	protected $principal;
	
	public function getStatus()
	{
		return $this->status;
	}
	
	public function setStatus($status)
	{
		switch($status)
		{
			case self::NO_CREDENTIALS:
			case self::WRONG_CREDENTIALS:
			case self::AUTHENTICATION_SUCCESSFUL:
			case self::AUTHENTICATION_NEEDED:
				
				$this->status = (int)$status;
				
			break;
			default:
				
				throw new SecurityException('Invalid authentication token status: ' . $status);
		}
	}
	
	public function getPrincipal()
	{
		return $this->principal;
	}
	
	public function setPrincipal(PrincipalInterface $principal)
	{
		$this->principal = $principal;
	}
}
