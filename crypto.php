<?php

define('ALGO', MCRYPT_RIJNDAEL_256);
define('MODE', MCRYPT_MODE_ECB);

ini_set('memory_limit', -1);

function initKeys($key) {
    srand((double)microtime()*1000000);
    $iv = mcrypt_create_iv(mcrypt_get_iv_size(ALGO, MODE), MCRYPT_RAND);
    $ks = mcrypt_get_key_size(ALGO, MCRYPT_MODE_ECB);
    $enc_key = substr(sha1($key), 0, $ks);
    return array($enc_key, $iv);
}

function myEncrypt($key, $data) {
    list($enc_key, $iv) = initKeys($key);
    $cipher = mcrypt_encrypt(ALGO, $enc_key, $data, MODE, $iv);
    return array(strlen($data),$cipher);
}

function myDecrypt($key, $cipher, $size) {
    list($enc_key, $iv) = initKeys($key);
    $plain = mcrypt_decrypt(ALGO, $enc_key, $cipher, MODE, $iv);
// size is important, since the decryption/encryption introduces null padding
    return substr($plain, 0, $size);
}
