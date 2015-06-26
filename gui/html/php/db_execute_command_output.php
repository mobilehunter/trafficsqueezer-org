<?php
//Read the DB and execute the frequently used command, so that system status is syncd in DB

error_reporting(5);
include("/var/www/html/c/c_db_access.php");
	
$query = "select id, command from command_output";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{ while($row = mysql_fetch_array($result))
	{
		$command =  $row['command'];
		$id =  $row['id'];
		print "executing: $command\n";
		$output = `$command`;
		mysql_query("update command_output set output=\"$output\" where id=$id", $db);
	}
}
mysql_close($db);