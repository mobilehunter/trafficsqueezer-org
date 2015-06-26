<?php include('c/c_check_login.php'); include("c/c_db_access.php"); include('c/c_g_var_set.php');
error_reporting(5);
session_start(); $username = $_SESSION['username'];
$_stats_history = $_POST['stats_history'];
$_stats_history_before = $_POST['stats_history_before'];
if( ($_stats_history_before != $_stats_history) )
{
    $query = "update profile set stats_history=\"$_stats_history\" where username='$username'";
    mysql_query($query, $db);
}

print "<meta HTTP-EQUIV=\"REFRESH\" content=\"0; url=stats_history.php\">";
?>
