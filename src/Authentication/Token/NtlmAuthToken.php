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

use KoolKode\Http\HttpRequest;
use KoolKode\Security\Authentication\NtlmAuthenticationProvider;
use KoolKode\Security\SecurityContextInterface;
use KoolKode\Security\SecurityUtil;

/**
 * State token being used in NTLMv2 authentication.
 * 
 * @author Martin Schröder
 * 
 * @link http://davenport.sourceforge.net/ntlm.html
 */
class NtlmAuthToken extends AbstractToken
{
	/**
	 * Null-terminated ASCII string "NTLMSSP" being used as message header in all NTLM messages.
	 * 
	 * @var string
	 */
	const NTLM_HEADER = "\x4E\x54\x4C\x4D\x53\x53\x50\x00";
	
	/**
	 * NTLMv2 Blob signature (first 4 bytes) and reserved NULL bytes (next 4 bytes).
	 * 
	 * @var string
	 */
	const NTLM_BLOB_HEADER = "\x01\x01\x00\x00\x00\x00\x00\x00";
	
	/**
	 * Data block 1: Server name
	 *
	 * @var integer
	 */
	const NTLM_TYPE_SERVER_NAME = 1;
	
	/**
	 * Data block 2: Domain name
	 *
	 * @var integer
	 */
	const NTLM_TYPE_DOMAIN_NAME = 2;
	
	/**
	 * Data block 3: Fully-qualified DNS host name (i.e., server.domain.com)
	 *
	 * @var integer
	 */
	const NTLM_TYPE_DNS_HOST_NAME = 3;
	
	/**
	 * Data block 4: DNS domain name (i.e., domain.com)
	 *
	 * @var integer
	 */
	const NTLM_TYPE_DNS_DOMAIN_NAME = 4;
	
	/**
	 * Indicates that Unicode strings are supported for use in security buffer data.
	 * 
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_UNICODE = 0x00000001;
	
	/**
	 * Indicates that OEM strings are supported for use in security buffer data.
	 * 
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_OEM = 0x00000002;
	
	/**
	 * Requests that the server's authentication realm be included in the Type 2 message.
	 *
	 * @var integer
	 */
	const NTLM_FLAG_REQUEST_TARGET = 0x00000004;
	
	/**
	 * Specifies that authenticated communication between the client and server should carry a digital signature (message integrity).
	 *
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_SIGN = 0x00000010;
	
	/**
	 * Specifies that authenticated communication between the client and server should be encrypted (message confidentiality).
	 *
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_SEAL = 0x00000020;
	
	/**
	 * Indicates that datagram authentication is being used.
	 *
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_DATAGRAM_STYLE = 0x00000040;
	
	/**
	 * Indicates that the Lan Manager Session Key should be used for signing and sealing authenticated communications.
	 *
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_LAN_MANAGER_KEY = 0x00000080;
	
	/**
	 * Indicates that NTLM authentication is being used.
	 *
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_NTLM = 0x00000200;
	
	/**
	 * Sent by the client in the Type 3 message to indicate that an anonymous context has been established.
	 *
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_ANONYMOUS = 0x00000800;
	
	/**
	 * Sent by the client in the Type 1 message to indicate that the name of the domain in which the client workstation has
	 * membership is included in the message.
	 * 
	 * This is used by the server to determine whether the client is eligible for local authentication.
	 *
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_DOMAIN_SUPPLIED = 0x00001000;
	
	/**
	 * Sent by the client in the Type 1 message to indicate that the client workstation's name is included in the message.
	 * 
	 * This is used by the server to determine whether the client is eligible for local authentication. 
	 *
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_WORKSTATION_SUPPLIED = 0x00002000;
	
	/**
	 * Sent by the server to indicate that the server and client are on the same machine.
	 * 
	 * Implies that the client may use the established local credentials for authentication instead of
	 * calculating a response to the challenge. 
	 *
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_LOCAL_CALL = 0x00004000;
	
	/**
	 * Indicates that authenticated communication between the client and server should be signed with a "dummy" signature.
	 *
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_ALWAYS_SIGN = 0x00008000;
	
	/**
	 * Sent by the server in the Type 2 message to indicate that the target authentication realm is a domain.
	 *
	 * @var integer
	 */
	const NTLM_FLAG_TARGET_TYPE_DOMAIN = 0x00010000;
	
	/**
	 * Sent by the server in the Type 2 message to indicate that the target authentication realm is a server.
	 *
	 * @var integer
	 */
	const NTLM_FLAG_TARGET_TYPE_SERVER = 0x00020000;
	
	/**
	 * Sent by the server in the Type 2 message to indicate that the target authentication realm is a share.
	 * 
	 * Presumably, this is for share-level authentication, usage is unclear.
	 * 
	 * @var integer
	 */
	const NTLM_FLAG_TARGET_TYPE_SHARE = 0x00040000;
	
	/**
	 * Indicates that the NTLM2 signing and sealing scheme should be used for protecting authenticated communications.
	 * 
	 * Note that this refers to a particular session security scheme, and is not related to the use of NTLMv2 authentication.
	 *
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_NTLM2_KEY = 0x00080000;
	
	/**
	 * Sent by the server in the Type 2 message to indicate that it is including a Target Information block in the message.
	 * 
	 * The Target Information block is used in the calculation of the NTLMv2 response.
	 *
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_TARGET_INFO = 0x00800000;
	
	/**
	 * Indicates that 128-bit encryption is supported.
	 *
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_128 = 0x20000000;
	
	/**
	 * Indicates that the client will provide an encrypted master key in the "Session Key" field of the Type 3 message.
	 *
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_KEY_EXCHANGE = 0x40000000;
	
	/**
	 * Indicates that 56-bit encryption is supported.
	 *
	 * @var integer
	 */
	const NTLM_FLAG_NEGOTIATE_56 = 0x80000000;
	
	protected $type;
	
	protected $username;
	
	protected $domain;
	
	protected $workstation;
	
	protected $clientHash;
	
	protected $clientBlob;
	
	protected $flags;
	
	protected $auth;
	
	protected $provider;
	
	protected $context;
	
	public function __construct(NtlmAuthenticationProvider $provider, SecurityContextInterface $context)
	{
		$this->provider = $provider;
		$this->context = $context;
	}
	
	public function getUsername()
	{
		return $this->username;
	}
	
	public function getDomain()
	{
		return $this->domain;
	}
	
	public function getWorkstation()
	{
		return $this->workstation;
	}
	
	public function isMessage1()
	{
		return $this->type === 1;
	}
	
	public function isMessage3()
	{
		return $this->type === 3;
	}
	
	public function updateCredentials(HttpRequest $request)
	{
		$this->setStatus(self::NO_CREDENTIALS);
		
		$this->type = NULL;
		$this->username = NULL;
		$this->domain = NULL;
		$this->workstation = NULL;
		$this->clientBlob = NULL;
		$this->clientHash = NULL;
		$this->flags = NULL;
		$this->auth = NULL;
		
		if('' === ($auth = trim($request->getHeader('Authorization', ''))))
		{
			return;
		}
		
		$parts = preg_split("'\s+'", $auth, 2);
		
		if(!is_array($parts) || count($parts) != 2 || strtoupper($parts[0]) !== 'NTLM')
		{
			return;
		}
		
		$this->setStatus(self::AUTHENTICATION_NEEDED);
		
		$auth = @base64_decode($parts[1]);
		
		if(self::NTLM_HEADER !== substr($auth, 0, 8))
		{
			return;
		}
		
		$this->auth = $auth;
		
		// Unpack the message type sent by the client, must be one of 1 or 3.
		$type = (int)$this->readUnsignedLong($this->auth, 8);
		
		if(1 == $type)
		{
			$this->type = 1;
			$this->flags = (int)$this->readUnsignedLong($this->auth, 12);
		}
		elseif(3 == $type)
		{
			$this->type = 3;
			
			$this->domain = $this->readSecurityBuffer($this->auth, 28);
			$this->username = $this->readSecurityBuffer($this->auth, 36);
			$this->workstation = $this->readSecurityBuffer($this->auth, 44);
			
			if(false !== strpos($this->username, '@'))
			{
				$tmp = explode('@', $this->username, 2);
				$this->username = trim($tmp[0]);
				$this->domain = trim($tmp[1]);
			}
			
			$ntlm = $this->readSecurityBuffer($this->auth, 20, false);
			
			$this->clientHash = (string)substr($ntlm, 0, 16);
			$this->clientBlob = (string)substr($ntlm, 16);
		}
	}
	
	public function getChallengeMessage($challenge)
	{
// 		$cflags = (int)$this->readUnsignedLong($this->auth, 12);
		
		$cdomain = $this->readSecurityBuffer($this->auth, 16);
		$ctarget = $this->readSecurityBuffer($this->auth, 24);
		
		$tname = $this->encodeUtf16($ctarget);
		
		$tdata = $this->encodeTargetInfo(self::NTLM_TYPE_DOMAIN_NAME, $this->encodeUtf16($cdomain));
		$tdata .= $this->encodeTargetInfo(self::NTLM_TYPE_SERVER_NAME, $this->encodeUtf16($ctarget));
		
		// OS version not needed here.
		$tdata .= "\x00\x00\x00\x00\x00\x00\x00\x00";
		
		$flags = self::NTLM_FLAG_NEGOTIATE_UNICODE;
		$flags |= self::NTLM_FLAG_NEGOTIATE_NTLM;
		$flags |= self::NTLM_FLAG_TARGET_TYPE_SHARE;
		$flags |= self::NTLM_FLAG_NEGOTIATE_TARGET_INFO;
		
		$message = self::NTLM_HEADER;
		$message .= "\x02\x00\x00\x00";
		$message .= pack('vvV', strlen($tname), strlen($tname), 48);
		$message .= pack('V', $flags);
		$message .= $challenge;
		
		// context only needed for local auth.
		$message .= "\x00\x00\x00\x00\x00\x00\x00\x00";
		
		$message .= pack('vvV', strlen($tdata), strlen($tdata), 48 + strlen($tname));
		
		return $message . $tname . $tdata;
	}
	
	/**
	 * Needs the MD4 hash of the UTF-16LE encoded password of the user in hex- or binary format.
	 * 
	 * @param string $username
	 * @param string $hash
	 * @param unknown $challenge
	 */
	public function isValidResponse($username, $hash, $challenge)
	{
		if(self::NTLM_BLOB_HEADER != substr($this->clientBlob, 0, 8))
		{
			return false;
		}
	
		// Timstamp, seconds since january 1, 1601, used in replay-attack prevention.
		// 	$str = (float)vsprintf('%u%04u%04u%04u', array_reverse(unpack('vt1/vt2/vt3/vt4', substr($this->clientBlob, 8, 8))));
		// 	$seconds = floor($str / 1000000);
	
		// Client nonce, useful in replay-attack prevention.
		// 	$cnonce = substr($this->clientBlob, 16, 8);
	
		if(!SecurityUtil::timingSafeEquals($username, $this->username))
		{
			return false;
		}
		
		if(!SecurityUtil::timingSafeEquals($this->provider->getDomain(), $this->domain))
		{
			return false;
		}
		
		$ntlmhash = $this->computeHmacMd5($hash, $this->encodeUtf16(strtoupper($this->username) . $this->domain));
		$hash = (string)$this->computeHmacMd5($ntlmhash, $challenge . $this->clientBlob);
		
		if(!SecurityUtil::timingSafeEquals($hash, $this->clientHash))
		{
			return false;
		}
		
		return true;
	}
	
	public function encodeUtf16($input)
	{
		return @iconv('UTF-8', 'UTF-16LE//IGNORE', $input);
	}
	
	public function computeMd4($input)
	{
		return hash('md4', $input, true);
	}
	
	public function computeHmacMd5($key, $input)
	{
		return hash_hmac('md5', $input, $key, true);
	}
	
	protected function hasAnyFlag($flags)
	{
		return ((int)$this->flags & $flags) != 0;
	}
	
	protected function hasAllFlag($flags)
	{
		return ((int)$this->flags & $flags) == $flags;
	}
	
	protected function encodeTargetInfo($type, $utf16)
	{
		return pack('vv', $type, strlen($utf16)) . $utf16;
	}
	
	protected function readUnsignedShort($input, $offset)
	{
		return @unpack('vr', substr($input, $offset, 2))['r'];
	}
	
	protected function readUnsignedLong($input, $offset)
	{
		return @unpack('Vr', substr($input, $offset, 4))['r'];
	}
	
	protected function readSecurityBuffer($input, $offset, $decodeUtf16 = true)
	{
		$len = (int)$this->readUnsignedShort($input, $offset);
// 		$alloc = (int)$this->readUnsignedShort($input, $offset + 2);
		$off = (int)$this->readUnsignedLong($input, $offset + 4);
		
		$result = substr($input, $off, $len);
	
		if($decodeUtf16)
		{
			$tmp = @iconv('UTF-16LE', 'UTF-8//IGNORE', $result);
	
			return ($tmp === false) ? $result : $tmp;
		}
	
		return $result;
	}
}
