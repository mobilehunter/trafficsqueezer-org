<?php include("c/c_db_access.php"); include('c/c_g_var_set.php'); session_start(); error_reporting(5);
$squid = $_GET['squid'];
set_port_lan_name($_GET['port'], $query, $db);

print "<meta HTTP-EQUIV=\"REFRESH\" content=\"0; url=w_wan_port.php\">";
?>