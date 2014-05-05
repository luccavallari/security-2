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

interface RequestMatcherInterface
{
	public function matchesRequest(HttpRequest $request);
}
