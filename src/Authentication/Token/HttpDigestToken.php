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

use KoolKode\Http\Entity\StreamEntity;
use KoolKode\Http\HttpRequest;
use KoolKode\Security\Authentication\HttpDigestAuthenticationProvider;
use KoolKode\Security\SecurityContextInterface;
use KoolKode\Security\SecurityException;
use KoolKode\Security\SecurityUtil;

/**
 * Token used in HTTP digest authentication.
 * 
 * @author Martin Schröder
 */
class HttpDigestToken extends AbstractToken
{
	/**
	 * Identity of the principal.
	 * 
	 * @var string
	 */
	protected $username;
	
	/**
	 * Authentication realm.
	 * 
	 * @var string
	 */
	protected $realm;
	
	/**
	 * Server-provided nonce value.
	 * 
	 * @var string
	 */
	protected $nonce;
	
	/**
	 * The request URI as it has been used during client hash generation.
	 * 
	 * @var string
	 */
	protected $uri;
	
	/**
	 * Quality of protection: needs to be one of "auth" or "auth-int".
	 * 
	 * @var string
	 */
	protected $qop;
	
	/**
	 * Nonce count (hex decimal).
	 * 
	 * @var string
	 */
	protected $nc;
	
	/**
	 * Client nonce value.
	 * 
	 * @var string
	 */
	protected $cnonce;
	
	/**
	 * Opaque value... unused as of now.
	 * 
	 * @var string
	 */
	protected $opaque;
	
	/**
	 * Hashed client response.
	 * 
	 * @var string
	 */
	protected $response;
	
	/**
	 * HA2 hash computed from data provided by the client.
	 * 
	 * @var string
	 */
	protected $ha2;

	/**
	 * Stale state of nonce to be set by authentication provider.
	 * 
	 * @var boolean
	 */
	protected $stale;
	
	protected $auth;
	
	protected $securityContext;
	
	public function __construct(HttpDigestAuthenticationProvider $auth, SecurityContextInterface $context)
	{
		$this->auth = $auth;
		$this->securityContext = $context;
	}
	
	public function getUsername()
	{
		return $this->username;
	}
	
	public function getRealm()
	{
		return $this->realm;
	}
	
	public function getNonce()
	{
		return $this->nonce;
	}
	
	public function getUri()
	{
		return $this->uri;
	}
	
	public function getQualityOfProtection()
	{
		return $this->qop;
	}
	
	public function getNonceCount()
	{
		return intval($this->nc, 16);
	}
	
	public function getClientNonce()
	{
		return $this->cnonce;
	}
	
	public function getOpaque()
	{
		return $this->opaque;
	}
	
	public function getResponse()
	{
		return $this->response;
	}
	
	public function getHA2()
	{
		return $this->ha2;
	}
	
	public function isStale()
	{
		return $this->stale;
	}
	
	public function setStale($stale)
	{
		$this->stale = $stale ? true : false;
	}
	
	/**
	 * {@inheritdoc}
	 */
	public function updateCredentials(HttpRequest $request)
	{
		$this->setStatus(self::NO_CREDENTIALS);
		$this->stale = false;
		
		$this->username = NULL;
		$this->realm = NULL;
		$this->nonce = NULL;
		$this->uri = NULL;
		$this->qop = NULL;
		$this->nc = NULL;
		$this->cnonce = NULL;
		$this->opaque = NULL;
		$this->response = NULL;
		$this->ha2 = NULL;
		
		if('' === ($auth = trim($request->getHeader('Authorization', ''))))
		{
			return;
		}
		
		$parts = preg_split("'\s+'", $auth, 2);
		
		if(!is_array($parts) || count($parts) != 2 || strtolower($parts[0]) !== 'digest')
		{
			return;
		}
		
		$digest = $this->parseDigest($parts[1], $request);
		
		$this->username = array_key_exists('username', $digest) ? (string)$digest['username'] : NULL;
		$this->realm = array_key_exists('realm', $digest) ? (string)$digest['realm'] : NULL;
		$this->nonce = array_key_exists('nonce', $digest) ? (string)$digest['nonce'] : NULL;
		$this->uri = $request->getRawUri();
		$this->qop = array_key_exists('qop', $digest) ? (string)$digest['qop'] : NULL;
		$this->nc = array_key_exists('nc', $digest) ? (string)$digest['nc'] : NULL;
		$this->cnonce = array_key_exists('cnonce', $digest) ? (string)$digest['cnonce'] : NULL;
		$this->opaque = array_key_exists('opaque', $digest) ? (string)$digest['opaque'] : NULL;
		$this->response = array_key_exists('response', $digest) ? (string)$digest['response'] : NULL;
		
		if($this->auth->getQualityOfProtection() == HttpDigestAuthenticationProvider::QOP_AUTH_INT)
		{
			$this->ha2 = md5(sprintf('%s:%s:%s', $request->getMethod(false), $this->uri, $this->computeContentMd5($request)));
		}
		else
		{
			$this->ha2 = md5(sprintf('%s:%s', $request->getMethod(false), $this->uri));
		}
		
		$this->setStatus(self::AUTHENTICATION_NEEDED);
	}
	
	/**
	 * Check if the response is valid using the given HA1 value.
	 * 
	 * @param string $ha1
	 * @return boolean
	 */
	public function isValidResponse($ha1)
	{
		if($this->opaque === NULL)
		{
			return false;
		}
		
		if(!SecurityUtil::timingSafeEquals($this->auth->getOpaque(), $this->opaque))
		{
			return false;
		}
		
		$args = [
			$ha1,
			$this->nonce,
			$this->nc,
			$this->cnonce,
			$this->auth->getQualityOfProtection(),
			$this->ha2
		];
		
		return SecurityUtil::timingSafeEquals(md5(vsprintf('%s:%s:%s:%s:%s:%s', $args)), $this->response);
	}
	
	/**
	 * Parse digest authentication header and return parsed key / value pairs.
	 *
	 * @param string $digest
	 * @param HttpRequest $request
	 * @return array<string, string>
	 */
	protected function parseDigest($digest, HttpRequest $request)
	{
		$required = [
			'nonce' => true,
			'username' => true,
			'response' => true,
			'cnonce' => true,
			'nc' => true
		];
	
		$tmp = [];
		$data = [];
	
		@preg_match_all("'(\w+)\s*=\s*(?:(?:\"((?:(?<!\\\\)[^\"])+)\")|([^,]+),)'U", $digest, $tmp, PREG_SET_ORDER);
	
		foreach($tmp as $m)
		{
			$data[$m[1]] = array_key_exists(3, $m) ? trim(trim($m[3]), '"') : trim(trim($m[2]), '"');
	
			unset($required[$m[1]]);
		}
		
		if(!empty($data['username']))
		{
			if(false !== strpos($data['username'], '\\\\'))
			{
				$tmp = explode('\\\\', $data['username']);
				
				$username = trim(array_pop($tmp), '"');
				$domain = trim(implode('\\\\', $tmp), '"');
				
				if($domain === $request->getHost())
				{
					$data['username'] = $username;
					$data['msdomain'] = $domain;
				}
			}
		}

		return (count($required) > 0) ? [] : $data;
	}
	
	/**
	 * Compute the content MD5 hash of the request body (streams request body contents to a
	 * temporary file and incrementaly computes the hash value replacing the requests input
	 * URL with the URL of the created file).
	 *
	 * @param HttpRequest $request
	 * @return string
	 */
	protected function computeContentMd5(HttpRequest $request)
	{
		if(!$request->hasEntity())
		{
			return md5('');
		}
		
		$hash = hash_init('md5');
		$in = $request->getEntity()->getInputStream();
		
		$tmp = new \SplTempFileObject();
		$fp = $tmp->openFile('wb', false);
		
		try
		{
			flock($fp, LOCK_EX);
		
			while(false !== ($chunk = $in->read()))
			{
				hash_update($hash, $chunk);
				fwrite($fp, $chunk);
			}
		}
		finally
		{
			@fclose($fp);
		}
		
		$request->setEntity(new StreamEntity($tmp->openFile('rb', false)));
	
		return hash_final($hash);
	}
}
