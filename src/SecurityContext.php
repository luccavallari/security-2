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
use KoolKode\Util\RandomGeneratorInterface;

/**
 * Basic security context implementation that can be mutated.
 * 
 * @author Martin Schröder
 */
class SecurityContext implements MutableSecurityContextInterface
{
	protected $principal;
	
	protected $session;
	
	protected $random;
	
	public function __construct(SessionInterface $session, RandomGeneratorInterface $random)
	{
		$this->session = $session;
		$this->random = $random;
		
		$this->principal = new AnonymousPrincipal();
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function getSession()
	{
		return $this->session;
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
		$prev = $this->principal;
		$this->principal = $principal;
		
		return $prev;
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function getRandomGenerator()
	{
		return $this->random;
	}
}
