<?php
	error_reporting(5);
    $dbHost = "localhost";
    $dbUser = "root";
    $dbPass = "welcome";
    $dbDatabase = "aquarium";
    $db = mysql_connect("$dbHost", "$dbUser", "$dbPass") or die ("Error connecting to database.");
    mysql_select_db("$dbDatabase", $db) or die ("Couldn't select the database.");

	 $file = fopen("/proc/trafficsqueezer/dpi_pop", "r") or exit("Unable to open file!");


	 while(!feof($file))
	 {
		 $buffer = fgets($file, 14096);
 		 foreach (preg_split("/(\r?\n)/", $buffer) as $line)
 		 {
 		 	//ignore any partial filled lines given by /proc !!
 		 	if(substr_count($line, ",")>=8) //atleast this many columns should exist in this row !
 		 	{
 				$array = split(",", $line);
				$jiffies      = $array[1];
				$src_ip       = $array[7];
				$dest_ip      = $array[8];
				$from      	  = $array[2];
				$to      	  = $array[3];
				$cc      	  = $array[4];
				$bcc          = $array[5];
				$subject      = $array[6];
 			
				$query = "insert into dpi_pop_log (jiffies,timestamp,src_ip,dst_ip,email_from,email_to,email_cc,email_bcc,subject) values ($jiffies, now(),\"$src_ip\",\"$dest_ip\",\"$from\",\"$to\",\"$cc\",\"$bcc\",\"$subject\")";
      			$result = mysql_query($query, $db);
      		}
		 }	
	 } 
	fclose($file);
?> 
