<?php
error_reporting(5);

$file = fopen("$argv[1]", "r");
if(!$file) { print "ERROR\n"; exit(); }
while(!feof($file))
{
	$buffer = fgets($file, 4096);
	print "$buffer";
}
fclose($file);
?>