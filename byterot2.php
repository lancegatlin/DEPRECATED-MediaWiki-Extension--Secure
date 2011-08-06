<?php

$wgExtensionFunctions[] = 'wfInitByteRotate2';

require_once ('secure.pwd');

function wfInitByteRotate2()
{
	global $gByteRotate2Key16, $gSecureHook;
	
	// Sig used to detect if text is encrypted or not
	$sig32 = md5('byterot2');
	$gSecureHook['sig32']['byterot2'] = $sig32;
	$gSecureHook['encrypt']['byterot2'] = 'ByteRotate2';
	$gSecureHook['decrypt'][$sig32] = 'ByteUnrotate2';
	
	// Key used by byte rotate functions
	$gByteRotate2Key16 = ByteRotate2_make_key16(SECURE_SERVER_PASSWORD);
}

function ByteRotate2_make_key16($t)
{
	$md5 = md5($t);
	$retv = array();
	for($i=0;$i<16;$i++)
		$retv[$i] = hexdec(substr($md5,$i*2,2));
	return $retv;
}

function ByteRotate2($t)
{
	global $gByteRotate2Key16;
	$key16 = $gByteRotate2Key16;

	$pi = 0;
	$len = strlen($t);

	for($i = 0;$i<$len;$i++)
	{
		$ascii = ord($t[$i]);
		$crc += $ascii;

		$ascii += $key16[$pi];
		$ascii %= 256;

		if($ascii < 16)
			$retv .= '0';
		$retv .= dechex($ascii);
		
		if(++$pi > 16)
			$pi = 0;
	}
	$crc %= 256;
	if($crc < 16)
		$t_crc .= '0';
	$t_crc .= dechex($crc);
	
	return $retv . $t_crc;
}

function ByteUnrotate2($t)
{
	global $gByteRotate2Key16;
	$key16 = $gByteRotate2Key16;
	
	$pi = 0;
	$len = strlen($t) - 2;

	if($len <= 0)
		return false;
		
	for($i = 0;$i < $len; $i += 2)
	{
		$ascii = hexdec(substr($t,$i,2));
		
		if($ascii < $key16[$pi])
			$ascii += (256 - $key16[$pi]);
		else $ascii -= $key16[$pi];
		$crc += $ascii;
		$retv .= chr($ascii);
		
		if(++$pi > 16)
			$pi = 0;
	};
	$crc %= 256;
	$t_crc = hexdec(substr($t,$len,2));
	
	if($crc != $t_crc)
		return false;
		
	return $retv;
};


?>