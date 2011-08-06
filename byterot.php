<?php

$wgExtensionFunctions[] = 'wfInitByteRotate';

require_once('secure.pwd');

function dout($t)
{
	$f = fopen('extensions/dout.txt', 'a+t');
	if(f === false)
		reutrn;
	
	fwrite($f, $t);
	fclose($f);
}

function wfInitByteRotate()
{
	global $gByteRotateKey16, $gSecureHook;
	
	// Sig used to detect if text is encrypted or not
	$sig32 = md5('byterot1');
//	$gSecureHook['sig32']['byterot1'] = $sig32;
//	$gSecureHook['encrypt']['byterot1'] = 'ByteRotate';
	$gSecureHook['decrypt'][$sig32] = 'ByteUnrotate';
	
	// Key used by byte rotate functions
//	$gByteRotateKey16 = make_key16(SECURE_SERVER_PASSWORD);
}

function make_key16($t)
{
	$md5 = md5($t);
	$retv = array();
	for($i=0;$i<16;$i++)
		$retv[$i] = hexdec(substr($md5,$i*2,2));
	return $retv;
}

function ByteRotate($t)
{
	global $gByteRotateKey16;
	$key16 = $gByteRotateKey16;

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
	$crc = dechex($crc % 256);
	
	return $retv . $crc;
}

function ByteUnrotate($t)
{
	global $gByteRotateKey16;
	$key16 = $gByteRotateKey16;
	
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