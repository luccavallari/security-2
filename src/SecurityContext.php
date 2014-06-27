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
use KoolKode\Util\RandomGenerator;

/**
 * @author Martin Schröder
 */
class SecurityContext implements MutableSecurityContextInterface
{
	protected $principal;
	protected $session;
	protected $random;
	
	public function __construct(SessionInterface $session, RandomGenerator $random)
	{
		$this->session = $session;
		$this->random = $random;
		
		$this->principal = new AnonymousPrincipal();
	}
	
	public function getSession()
	{
		return $this->session;
	}
	
	public function getPrincipal()
	{
		return $this->principal;
	}
	
	public function setPrincipal(PrincipalInterface $principal)
	{
		$this->principal = $principal;
	}
	
	public function getRandomGenerator()
	{
		return $this->random;
	}
}
