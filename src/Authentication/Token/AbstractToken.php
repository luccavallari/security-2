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
use KoolKode\Security\SecurityException;

/**
 * @author Martin Schröder
 */
abstract class AbstractToken implements TokenInterface
{
	protected $status = self::NO_CREDENTIALS;
	
	protected $principal;
	
	/**
	 * {@inheritdoc}
	 */
	public function getStatus()
	{
		return $this->status;
	}
	
	/**
	 * {@inheritdoc}
	 */
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
	
	/**
	 * {@inheritdoc}
	 */
	public function getPrincipal()
	{
		return $this->principal;
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function setPrincipal(PrincipalInterface $principal)
	{
		$this->principal = $principal;
	}
}
