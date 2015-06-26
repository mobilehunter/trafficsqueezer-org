<?php
//Read the DB and push this job(config) into kernel via "io" /proc file

$proc_io_file = "/proc/trafficsqueezer/io";
error_reporting(5);
include("/var/www/html/c/c_db_access.php");	
	
$query = "select id, kernel_job from kernel_jobs";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{ while($row = mysql_fetch_array($result))
	{
		$kernel_job =  $row['kernel_job'];
		$id =  $row['id'];
		$command = "echo \"$kernel_job\" > $proc_io_file ";
		print "$command \n"; system($command);

		mysql_query("delete from kernel_jobs where id=$id", $db);
	}
}
mysql_close($db);
