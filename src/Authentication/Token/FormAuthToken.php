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

use KoolKode\Http\Http;
use KoolKode\Http\HttpRequest;
use KoolKode\Http\Uri;
use KoolKode\Security\Authentication\FormAuthenticationProvider;
use KoolKode\Security\SecurityContextInterface;

/**
 * Authentication token used by form-based authentication.
 * 
 * @author Martin Schröder
 */
class FormAuthToken extends AbstractToken
{
	/**
	 * The identity of the principal.
	 *
	 * @var string
	 */
	protected $username = '';
	
	/**
	 * The cleartext apssword of the principal.
	 *
	 * @var string
	 */
	protected $password = '';
	
	/**
	 * Check if the guard token matched.
	 * 
	 * @var boolean
	 */
	protected $guarded = false;
	
	protected $auth;
	
	protected $securityContext;
	
	public function __construct(FormAuthenticationProvider $auth, SecurityContextInterface $context)
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
	
	/**
	 * Check if the request has been protected with a POST-submitted guard token that
	 * matches the guard token set in the session.
	 * 
	 * @return boolean
	 */
	public function isGuarded()
	{
		return $this->guarded;
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function updateCredentials(HttpRequest $request)
	{
		$this->setStatus(self::AUTHENTICATION_NEEDED);
		
		$path = trim($request->getUri()->getPath(false), '/');
		$logoutPath = trim((new Uri($this->auth->getLogoutUri()))->getPath(false), '/');
		
		if($path === $logoutPath)
		{
			return;
		}
		
		$session = $this->securityContext->getSession();
		
		if($session->isInitialized())
		{
			$data = (array)$session->get($this->auth->getKey(), NULL);
			$identity = NULL;
			
			if(isset($data[FormAuthenticationProvider::SESSION_IDENTITY]))
			{
				$identity = (string)$data[FormAuthenticationProvider::SESSION_IDENTITY];
			}
			
			if($identity !== NULL)
			{
				$principal = $this->auth->getPrincipalProvider()->findPrincipal($identity);
				
				if($principal !== NULL)
				{
					$this->setPrincipal($principal);
					
					return $this->setStatus(self::AUTHENTICATION_SUCCESSFUL);
				}
			}
		}
		
		if($request->isPost(false) && $request->getMediaType()->is(Http::FORM_ENCODED))
		{
			$fields = $request->getEntity()->getFields();
			$data = isset($fields['auth']) ? (array)$fields['auth'] : [];
			$data = isset($data[$this->auth->getKey()]) ? (array)$data[$this->auth->getKey()] : [];
			
			if(array_key_exists(FormAuthenticationProvider::FIELD_USERNAME, $data))
			{
				$this->username = (string)$data[FormAuthenticationProvider::FIELD_USERNAME];
			}
			
			if(array_key_exists(FormAuthenticationProvider::FIELD_PASSWORD, $data))
			{
				$this->password = (string)$data[FormAuthenticationProvider::FIELD_PASSWORD];
			}
			
			if(array_key_exists(FormAuthenticationProvider::FIELD_GUARD, $data))
			{
				$guard = (string)$data[FormAuthenticationProvider::FIELD_GUARD];
				$data = (array)$session->get($this->auth->getKey(), NULL);
				
				if(array_key_exists(FormAuthenticationProvider::SESSION_GUARD, $data))
				{
					if((string)$data[FormAuthenticationProvider::SESSION_GUARD] === $guard)
					{
						$this->guarded = true;
					}
				}
			}
			
			return $this->setStatus(self::AUTHENTICATION_NEEDED);
		}
	}
}
