<?php

/*
 * This file is part of KoolKode Security.
*
* (c) Martin Schröder <m.schroeder2007@gmail.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

// FIXME: Decouple from container.
// FIXME: SecurityContext and session must be coupled (replacing sessions is no good)!

namespace KoolKode\Security;

use KoolKode\Context\ContainerInterface;
use KoolKode\Session\SessionInitializedEvent;
use KoolKode\Session\TransientSession;
use KoolKode\Session\SessionCloseEvent;
use KoolKode\Session\SessionInterface;
use KoolKode\Util\RandomGenerator;

/**
 * @author Martin Schröder
 */
class SecurityContext implements MutableSecurityContextInterface
{
	protected $principal;
	protected $session;
	
	protected $container;
	
	public function __construct(ContainerInterface $container)
	{
		$this->container = $container;
		
		$this->principal = new AnonymousPrincipal();
		$this->removeSession();
	}
	
	public function getSession()
	{
		return $this->session;
	}
	
	public function setSession(SessionInterface $session)
	{
		$this->session = $session;
	}
	
	public function removeSession()
	{
		$this->session = $this->container->get('KoolKode\Session\TransientSession');	
		$this->session->initialize();
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
		return new RandomGenerator();
	}
}
