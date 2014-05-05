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

use KoolKode\Http\HttpRequest;
use KoolKode\Http\HttpResponse;
use KoolKode\Security\Authentication\Token\TokenInterface;

/**
 * Entry point start the authentication process.
 * 
 * @author Martin Schröder
 */
interface EntryPointInterface
{
	/**
	 * Authentication is started by populating the given HTTP response with headers and / or an entity.
	 * 
	 * @param TokenInterface $token
	 * @param HttpRequest $request
	 * @param HttpResponse $response
	 */
	public function startAuthentication(TokenInterface $token, HttpRequest $request, HttpResponse $response);
}
