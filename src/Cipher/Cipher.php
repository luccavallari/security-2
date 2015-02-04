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

use KoolKode\Security\SecurityUtil;

/**
 * @author Martin Schröder
 */
class Cipher {

    /**
     * @var CipherConfig
     */
    protected $config;

    public function __construct(CipherConfig $config)
    {
        $this->config = clone $config;
    }

    /**
     * Decrypts a message with auhtenticity check.
     *
     * @param string $message Encoded message.
     * @return mixed Plaintext message.
     *
     * @throws IntegrityCheckFailedException
     */
    public function decryptMessage($message)
    {
        $calgo = $this->config->getCipherAlgorithm();
        $cmode = $this->config->getCipherMode();
        $malgo = $this->config->getHmacAlgorithm();
        
        $size = mcrypt_get_iv_size($calgo, $cmode);
        $keySize = mcrypt_get_key_size($calgo, $cmode);
        $hmacSize = strlen(hash_hmac($malgo, '', 'foo-key', true));

        $cmac = substr($message, -1 * $hmacSize);
        $iv = substr($message, 0, $size);
        $cipherText = substr($message, $size, -1 * $hmacSize);
        $hmac = hash_hmac($malgo, $iv . $cipherText, $this->computeCipherKey($this->config->getHmacKey(), $hmacSize, $iv), true);
        
        if(!SecurityUtil::timingSafeEquals($hmac, $cmac))
        {
            throw new IntegrityCheckFailedException('Invalid encrypted input message detected');
        }
        
        $key = $this->computeCipherKey($this->config->getCipherKey(), $keySize, $iv);
        $data = mcrypt_decrypt($calgo, $key, $cipherText, $cmode, $iv);
        
        // PKCS7 Padding
        $pad = ord($data[strlen($data) - 1]);
        $data = substr($data, 0, -1 * $pad);
        
        // Remove zero-byte padding from the string.
        return $data;
    }

    /**
     * Encrypts the given message and adds an authenticity code.
     *
     * <pre><b>CIPHERTEXT</b> := IV + ENCRYPT(CLEARTEXT, PBKDF(ENCRYPTION_KEY))
     * <b>MESSAGE</b> := CIPHERTEXT + HMAC(CIPHERTEXT, PBKDF(HMAC_KEY))
     * </pre>
     *
     * @param string $input Plaintext message.
     * @return string Encrypted message.
     */
    public function encryptMessage($input)
    {
        $input = (string)$input;
        
        $calgo = $this->config->getCipherAlgorithm();
        $cmode = $this->config->getCipherMode();
        $malgo = $this->config->getHmacAlgorithm();
        
        $size = mcrypt_get_iv_size($calgo, $cmode);
        $keySize = mcrypt_get_key_size($calgo, $cmode);
        $blockSize = mcrypt_get_block_size($calgo, $cmode);
        $hmacSize = strlen(hash_hmac($malgo, '', 'foo-key', true));
        
        $iv = openssl_random_pseudo_bytes($size);
        $key = $this->computeCipherKey($this->config->getCipherKey(), $keySize, $iv);
        
        // PKCS7 Padding
        $pad = $blockSize - (strlen($input) % $blockSize);
        $input .= str_repeat(chr($pad), $pad);
        
        $cipherText = $iv . mcrypt_encrypt($calgo, $key, $input, $cmode, $iv);
        
        return $cipherText . hash_hmac($malgo, $cipherText, $this->computeCipherKey($this->config->getHmacKey(), $hmacSize, $iv), true);
    }
    
    protected function computeCipherKey($key, $length, $salt)
    {
        return hash_pbkdf2($this->config->getPbkdfAlgorithm(), $key, $salt, $this->config->getPbkdfIterations(), $length, true);
    }
}
