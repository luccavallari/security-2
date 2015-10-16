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
 * Basic security context implementation that can be mutated.
 * 
 * @author Martin Schröder
 */
class SecurityContext implements MutableSecurityContextInterface
{
	protected $principal;
	
	protected $session;
	
	
	public function __construct(SessionInterface $session)
	{
		$this->session = $session;
		
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
}
