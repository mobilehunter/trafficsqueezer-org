<?php include("/var/www/html/c/c_db_access.php");


$file = fopen("/etc/resolv.conf", "r") or exit("Unable to open file!");
while(!feof($file))
{
	 $buffer = fgets($file, 4096);
	 if(!strncmp($buffer, "nameserver ", strlen("nameserver ")))
	 {
			$array = explode(' ', $buffer);
			$ip  = trim($array[1]);
			
			$query = "insert into nameserver (nameserver_ip) values ('$ip')";
      	mysql_query($query, $db);
	 }

}
fclose($file);


?>
