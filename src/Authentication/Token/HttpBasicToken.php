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

use KoolKode\Http\HttpRequest;
use KoolKode\Security\Authentication\HttpBasicAuthenticationProvider;
use KoolKode\Security\SecurityContextInterface;

/**
 * Token used in HTTP basic authentication.
 * 
 * @author Martin Schröder
 */
class HttpBasicToken extends AbstractToken
{
	/**
	 * The identity of the principal.
	 * 
	 * @var string
	 */
	protected $username;
	
	/**
	 * The cleartext apssword of the principal.
	 * 
	 * @var string
	 */
	protected $password;
	
	protected $auth;
	protected $securityContext;
	
	public function __construct(HttpBasicAuthenticationProvider $auth, SecurityContextInterface $context)
	{
		$this->auth = $auth;
		$this->securityContext = $context;
	}
	
	/**
	 * Get the identity of the principal.
	 * 
	 * @return string
	 */
	public function getUsername()
	{
		return $this->username;
	}
	
	/**
	 * Get the cleartext password of the principal.
	 * 
	 * @return string
	 */
	public function getPassword()
	{
		return $this->password;
	}
	
	public function updateCredentials(HttpRequest $request)
	{
		$this->setStatus(self::NO_CREDENTIALS);
		
		$this->username = NULL;
		$this->password = NULL;
		
		if('' === ($auth = trim($request->getHeader('Authorization', ''))))
		{
			return;
		}
		
		$parts = preg_split("'\s+'", $auth, 2);
		
		if(!is_array($parts) || count($parts) != 2 || strtolower($parts[0]) !== 'basic')
		{
			return;
		}
		
		$credentials = explode(':', (string)@base64_decode($parts[1]), 2);
		
		if(!is_array($credentials) || count($credentials) != 2)
		{
			return;
		}
		
		$username = $credentials[0];
		
		if(false !== ($index = strrpos($username, '\\\\')))
		{
			$username = substr($username, $index + 1);
		}
		
		$this->username = trim($username);
		$this->password = trim($credentials[1]);
		
		$this->setStatus(self::AUTHENTICATION_NEEDED);
	}
}
