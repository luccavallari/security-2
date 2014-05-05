<?php

/*
 * This file is part of KoolKode Security.
*
* (c) Martin Schröder <m.schroeder2007@gmail.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

namespace KoolKode\Security\Firewall;

use KoolKode\Http\HttpRequest;
use KoolKode\Http\HttpResponse;

interface FirewallInterface
{
	const AUTH_ONE = 1;
	const AUTH_AT_LEAST_ONE = 2;
	const AUTH_ALL = 3;
	
	public function isAuthenticated();
	
	public function authenticate(HttpRequest $request);
	
	public function matchesRequest(HttpRequest $request);
	
	public function interceptRequest(HttpRequest $request);
	
	public function interceptResponse(HttpRequest $request, HttpResponse $response);
}
