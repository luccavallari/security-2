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

use KoolKode\Http\Http;
use KoolKode\Http\HttpRequest;
use KoolKode\Http\HttpResponse;
use KoolKode\Http\UriBuilder;
use KoolKode\Security\Firewall\RequestInterceptorInterface;

/**
 * @author Martin Schröder
 */
class ChannelSwitcher implements RequestInterceptorInterface
{
	protected $secure;
	
	protected $priority;
	
	public function __construct($secure = true, $priority = 0)
	{
		$this->secure = $secure ? true : false;
		$this->priority = (int)$priority;
	}
	
	public function getRequestInterceptorPriority()
	{
		return $this->priority;
	}
	
	public function interceptRequest(HttpRequest $request)
	{
		if($this->secure && !$request->isSecure())
		{
			$response = new HttpResponse(Http::REDIRECT_IDENTICAL);
			$response->setHeader('Location', $request->getUri()->setScheme('https'));
			
			return $response;
		}
		
		if(!$this->secure && $request->isSecure())
		{
			$response = new HttpResponse(Http::REDIRECT_IDENTICAL);
			$response->setHeader('Location', $request->getUri()->setScheme('http'));
				
			return $response;
		}
	}
}
