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

interface ResponseInterceptorInterface
{
	public function getResponseInterceptorPriority();
	
	/**
	 * Intercept the HTTP response allowing to mutate or replace the generated response.
	 * 
	 * @param HttpRequest $request
	 * @param HttpResponse $response
	 * @return HttpResponse The response to be sent, will replace the given response.
	 */
	public function interceptResponse(HttpRequest $request, HttpResponse $response);
}
