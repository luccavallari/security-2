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

interface RequestInterceptorInterface
{
	public function getRequestInterceptorPriority();
	
	/**
	 * Intercept the HTTP request, the given requets can be mutated.
	 * 
	 * @param HttpRequest $request
	 * @return HttpResponse or NULL, will terminate and send the response if not NULL.
	 */
	public function interceptRequest(HttpRequest $request);
}
