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

/**
 * @author Martin Schröder
 */
class CipherConfig
{
    protected $cipherAlgorithm = MCRYPT_RIJNDAEL_128;
    
    protected $cipherMode = MCRYPT_MODE_CBC;
    
    protected $hmacAlgorithm = 'sha1';
    
    protected $pbkdfAlgorithm = 'sha256';
    
    protected $pbkdfIterations = 4096;

    protected $cipherKey;
    
    protected $hmacKey;

    public function __construct($cipherKey, $hmacKey)
    {
        $this->setCipherKey($cipherKey);
        $this->setHmacKey($hmacKey);
    }

    public function getCipherAlgorithm()
    {
        return $this->cipherAlgorithm;
    }

    public function setCipherAlgorithm($cipherAlgorithm)
    {
        static $algos = NULL;
        
        if($algos === NULL)
        {
            $algos = (array)mcrypt_list_algorithms();
        }
        
        $algo = (string)$cipherAlgorithm;
        
        if(!in_array($algo, $algos, true))
        {
            $allow = implode(', ', array_map(function($el) {
                return '"' . $el . '"';
            }, $algos));
            
            throw new \InvalidArgumentException(sprintf('Invalid cipher "%s" given, supported ciphers are %s', $algo, $allow));
        }
        
        $this->cipherAlgorithm = $algo;
        
        return $this;
    }

    public function getCipherMode()
    {
        return $this->cipherMode;
    }

    public function setCipherMode($cipherMode)
    {
        switch ($cipherMode)
        {
            case MCRYPT_MODE_CBC:
            case MCRYPT_MODE_CFB:
                $this->cipherMode = $cipherMode;
                break;
            default:
                throw new \InvalidArgumentException(sprintf('Unsupported cipher mode, allowed modes are MCRYPT_MODE_CBC and MCRYPT_MODE_CFB'));
        }
        
        return $this;
    }

    public function getHmacAlgorithm()
    {
        return $this->hmacAlgorithm;
    }

    public function setHmacAlgorithm($hmacAlgorithm)
    {
        $algo = (string)$hmacAlgorithm;
        $supported = $this->getHashAlgorithms();
        
        if(!in_array($algo, $supported, true))
        {
            $allow = implode(', ', array_map(function($el) {
                return '"' . $el . '"';
            }, $supported));
        
         	throw new \InvalidArgumentException(sprintf('Hash algorithm "%s" not supported, allowed algorithms are %s', $algo, $allow));
        }
        
        $this->hmacAlgorithm = $algo;
        
        return $this;
    }

    public function getPbkdfAlgorithm()
    {
        return $this->pbkdfAlgorithm;
    }

    public function setPbkdfAlgorithm($pbkdfAlgorithm)
    {
        $algo = (string)$pbkdfAlgorithm;
        $supported = $this->getHashAlgorithms();
        
        if(!in_array($algo, $supported, true))
        {
            $allow = implode(', ', array_map(function($el) {
                return '"' . $el . '"';
            }, $supported));
            
            throw new \InvalidArgumentException(sprintf('Hash algorithm "%s" not supported, allowed algorithms are %s', $algo, $allow));
        }
        
        $this->pbkdfAlgorithm = $algo;
        
        return $this;
    }

    public function getPbkdfIterations()
    {
        return $this->pbkdfIterations;
    }

    public function setPbkdfIterations($pbkdfIterations)
    {
        $it = (int)$pbkdfIterations;
        
        if($it < 1)
        {
            throw new \InvalidArgumentException(sprintf('PBKDF iterations must be at least 1'));
        }
        
        if($it > 10000)
        {
            throw new \InvalidArgumentException(sprintf('PBKDF iterations must not exceed 10000'));
        }
        
        $this->pbkdfIterations = $it;
        
        return $this;
    }

    public function getCipherKey()
    {
        return $this->cipherKey;
    }

    public function setCipherKey($cipherKey)
    {
        $key = (string)$cipherKey;
        
        if(strlen($key) < 32)
        {
            throw new \InvalidArgumentException(sprintf('Cipher key must be at least 32 bytes in length'));
        }
        
        $this->cipherKey = $key;
        
        return $this;
    }

    public function getHmacKey()
    {
        return $this->hmacKey;
    }

    public function setHmacKey($hmacKey)
    {
        $key = (string)$hmacKey;
        
        if(strlen($key) < 32)
        {
            throw new \InvalidArgumentException(sprintf('HMAC key must be at least 32 bytes in length'));
        }
        
        $this->hmacKey = $key;
        
        return $this;
    }
    
    protected function getHashAlgorithms()
    {
        static $algos = NULL;
        
        if($algos === NULL)
        {
            $algos = (array)hash_algos();
        }
        
        return $algos;
    }
}
