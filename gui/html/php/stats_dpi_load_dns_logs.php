<?php
	error_reporting(5);
    $dbHost = "localhost";
    $dbUser = "root";
    $dbPass = "welcome";
    $dbDatabase = "aquarium";
    $db = mysql_connect("$dbHost", "$dbUser", "$dbPass") or die ("Error connecting to database.");
    mysql_select_db("$dbDatabase", $db) or die ("Couldn't select the database.");

	 $file = fopen("/proc/trafficsqueezer/dpi_dns_request", "r") or exit("Unable to open file!");


	 while(!feof($file))
	 {
		 $buffer = fgets($file, 14096);
		 print "$buffer";
 		 foreach (preg_split("/(\r?\n)/", $buffer) as $line)
 		 {
 		 	//ignore any partial filled lines given by /proc !!
 		 	if(substr_count($line, ",")>=4) //atleast this many columns should exist in this row !
 		 	{
 				$array = split(",", $line);
				$request_type = NULL;
				$jiffies      = $array[1];
				$domain       = $array[2];
				$src_ip       = $array[3];
				$dest_ip      = $array[4];
 			
				$query = "insert into dpi_dns_request_log (jiffies, timestamp,request_type,src_ip,dst_ip,domain) values ($jiffies, now(),'$request_type',\"$src_ip\",\"$dest_ip\",\"$domain\")";
      			$result = mysql_query($query, $db);
      		}
		 }	
	 } 
	fclose($file);
?> 


