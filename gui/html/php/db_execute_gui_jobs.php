<?php
//Execute "root" context GUI jobs.
error_reporting(5); include("/var/www/html/c/c_db_access.php");
	
$query = "select id, job from gui_jobs";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{ while($row = mysql_fetch_array($result))
	{
		$job =  $row['job'];
		$id =  $row['id'];
		$output = `$job`;
		mysql_query("delete from gui_jobs where id=$id", $db);
	}
}
mysql_close($db);