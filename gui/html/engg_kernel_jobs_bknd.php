<?php include('c/c_check_login.php'); include("c/c_db_access.php"); include('c/c_g_var_set.php'); error_reporting(5);
$query = "delete from kernel_jobs where 1=1";
mysql_query($query, $db);
print "<meta HTTP-EQUIV=\"REFRESH\" content=\"0; url=engg_kernel_jobs.php\">";
?>