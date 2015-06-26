<?php
	error_reporting(5);
    $dbHost = "localhost";
    $dbUser = "root";
    $dbPass = "welcome";
    $dbDatabase = "aquarium";
    $db = mysql_connect("$dbHost", "$dbUser", "$dbPass") or die ("Error connecting to database.");
    mysql_select_db("$dbDatabase", $db) or die ("Couldn't select the database.");

	 $file = fopen("/proc/trafficsqueezer/dpi_http_access", "r") or exit("Unable to open file!");

	 while(!feof($file))
	 {
	 	$buffer = fgets($file, 14096);
 		foreach (preg_split("/(\r?\n)/", $buffer) as $line)
 		{
 			//ignore any partial filled lines given by /proc !!
 		 	if(substr_count($line, ",")>=7) //atleast this many columns should exist in this row !
 		 	{
 				$array = split(",", $line);
 				$jiffies      = $array[0];
 				$request_type = $array[7];
 				if($request_type==NULL) { $request_type = '-'; }
 				$src_ip  = $array[5];
 				$dest_ip = $array[6];
 				$domain  = $array[2];
 				$content = $array[3];
 				$browser = $array[4];

				$query = "insert into dpi_http_access_log (jiffies,timestamp,request_type,src_ip,dst_ip,domain,content,browser) values ($jiffies, now(),'$request_type',\"$src_ip\",\"$dest_ip\",\"$domain\",\"$content\",\"$browser\")";
         		$result = mysql_query($query, $db);
         	}
		}
	}
	fclose($file);
?> 


