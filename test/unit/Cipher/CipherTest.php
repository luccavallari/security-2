<?php

/*
 * This file is part of KoolKode Security.
 *
 * (c) Martin Schröder <m.schroeder2007@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace KoolKode\Security\Cipher;

class CipherTest extends \PHPUnit_Framework_TestCase
{
	public function testEncryptDecrypt()
	{
		$config = new CipherConfig(md5('foo'), md5('bar'));
		$cipher = new Cipher($config);
		$message = 'Hello world :)';
		
		$ciphertext = $cipher->encryptMessage($message);
		$cleartext = $cipher->decryptMessage($ciphertext);
		
		$this->assertEquals($message, $cleartext);
	}
	
	/**
	 * @expectedException \KoolKode\Security\Cipher\IntegrityCheckFailedException
	 */
	public function testDetectsModification()
	{
		$config = new CipherConfig(md5('foo'), md5('bar'));
		$cipher = new Cipher($config);
		
		$ciphertext = $cipher->encryptMessage('Hello foo!');
		$ciphertext .= 'E';
		
		$cipher->decryptMessage($ciphertext);
	}
}
