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
 * Uses multiple (mixed) sources of randomness and mixes them together using
 * an approach based on HMAC.
 * 
 * @author Martin Schröder
 */
class RandomGenerator
{
	protected static $random;
	protected static $urandom;
	protected static $openSSL;
	protected static $capicom;
	
	public function __construct()
	{
		if(self::$random === NULL)
		{
			self::$random = @is_file('/dev/random');
		}
		
		if(self::$urandom === NULL)
		{
			self::$urandom = @is_file('/dev/urandom');
		}
		
		if(self::$openSSL === NULL)
		{
			self::$openSSL = @function_exists('openssl_random_pseudo_bytes');
		}
		
		if(self::$capicom === NULL)
		{
			self::$capicom = @class_exists('COM', false);
		}
	}
	
	/**
	 * Generates random bytes.
	 * 
	 * @param integer $length The byte count to be generated.
	 * @return string
	 * 
	 * @throws \InvalidArgumentException When an invalid byte count has been passed.
	 */
	public function generateRandom($length)
	{
		$length = (int)$length;
		
		if($length < 1 || $length > 100000)
		{
			throw new \InvalidArgumentException(sprintf('Unable to generate %d random bytes', $length));
		}
		
		$parts = [];
		
		// rand:
		$str = '';
		
		for($i = 0; $i < $length; $i++)
		{
			$str .= chr((rand() ^ rand()) % 255);
		}
		
		$parts[] = $str;
		
		// MT rand:
		$str = '';
        
        for($i = 0; $i < $length; $i++)
		{
			$str .= chr((mt_rand() ^ mt_rand()) % 256);
		}
		
		$parts[] = $str;
		
		// uniquid:
		$str = '';
		
		while(strlen($str) < $length)
		{
			$str = uniqid($str, true);
		}
		
		$parts[] = substr($str, 0, $length);
		
		if(self::$random)
		{
			$fp = @fopen('/dev/random', 'rb');
			
			if($fp !== false)
			{
				$parts[] = fread($fp, $length);
				@fclose($fp);
			}
		}
		
		if(self::$urandom)
		{
			$fp = @fopen('/dev/urandom', 'rb');
			
			if($fp !== false)
			{
				$parts[] = fread($fp, $length);
				@fclose($fp);
			}
		}
        
		if(self::$capicom)
		{
			$capi = new \COM('CAPICOM.Utilities.1');
			$parts[] = str_pad(base64_encode(base64_encode($util->GetRandom($size, 0))), $length, chr(0));
		}
		
		if(self::$openSSL)
		{
			$parts[] = openssl_random_pseudo_bytes($length);
		}
		
		// Mix sources using HMAC:
		$result = '';
		$stub = $parts[0];
		$size = count($parts);
		$offset = 0;
		
		foreach($parts as $i => $part)
		{
			$key = ($i + $offset) % $size;
			
			if($i & 1)
			{
				$stub ^= hash_hmac('sha512', $stub, $key, true);
			}
			else
			{
				$stub ^= hash_hmac('sha512', $key, $stub, true);
			}
			
			$offset = ($offset + 1) % $size;
		}
		
		return substr($result .= $stub, 0, $length);
	}
}
