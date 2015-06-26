<?php
	error_reporting(5);
	$source_type = $argv[1];
	$domain_name = $argv[2];
   $dest_ip = $argv[3];
	
	$dbHost = "localhost";
   $dbUser = "root";
   $dbPass = "welcome";
   $dbDatabase = "aquarium";
   $db = mysql_connect("$dbHost", "$dbUser", "$dbPass") or die ("Error connecting to database.");
   mysql_select_db("$dbDatabase", $db) or die ("Couldn't select the database.");

	
   $query = "insert into dns_cache (timestamp, type, domain, dest) values (now(), \"$source_type\", \"$domain_name\", \"$dest_ip\")";
   mysql_query($query, $db);

   mysql_close($db);
?>
