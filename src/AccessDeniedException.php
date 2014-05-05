<?php

/*
 * This file is part of KoolKode Security.
*
* (c) Martin Schröder <m.schroeder2007@gmail.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

namespace KoolKode\Security;

/**
 * Is thrown when a principal is authenticated but does not have permission to
 * access a protected resource.
 * 
 * @author Martin Schröder
 */
class AccessDeniedException extends SecurityException { }
