<?php

/*
 * This file is part of KoolKode Security.
 *
 * (c) Martin Schröder <m.schroeder2007@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace KoolKode\Security\Authentication\EntryPoint;

use KoolKode\Http\Http;
use KoolKode\Http\HttpRequest;
use KoolKode\Http\HttpResponse;
use KoolKode\Security\Authentication\NtlmAuthenticationProvider;
use KoolKode\Security\Authentication\Token\NtlmAuthToken;
use KoolKode\Security\Authentication\Token\TokenInterface;
use KoolKode\Security\SecurityContextInterface;
use KoolKode\Security\SecurityException;

class NtlmAuth implements EntryPointInterface
{
	protected $provider;
	
	protected $context;
	
	public function __construct(NtlmAuthenticationProvider $provider, SecurityContextInterface $context)
	{
		$this->provider = $provider;
		$this->context = $context;
	}
	
	public function startAuthentication(TokenInterface $token, HttpRequest $request, HttpResponse $response)
	{
		if(!$token instanceof NtlmAuthToken)
		{
			throw new SecurityException(sprintf('Invalid token %s passed to %s', get_class($token), get_class($this)));
		}
		
		$response->setStatus(Http::CODE_UNAUTHORIZED);
		$response->setReason(Http::getReason(Http::CODE_UNAUTHORIZED));
		
		if($token->isMessage3())
		{
			$message = $token->getChallengeMessage($this->provider->createChallenge($this->context));
			
			$response->addHeader('WWW-Authenticate', sprintf('NTLM %s', base64_encode($message)));
		}
		else
		{
			$response->addHeader('WWW-Authenticate', 'NTLM');
		}
	}
}
