<?php include('c/c_body_bknd.php'); include("c/c_db_access.php"); include('c/c_g_var_set.php'); error_reporting(5);

$_port_direction = $_POST['port_direction'];
$_port_name = $_POST['port_name'];

set_port($_port_name, $_port_direction, $query, $db);

print "<meta HTTP-EQUIV=\"REFRESH\" content=\"0; url=ports.php\">";
?>