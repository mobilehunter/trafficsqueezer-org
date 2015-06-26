<?php include('c/c_check_login.php'); include("c/c_db_access.php"); include('c/c_g_var_set.php');
error_reporting(5);

$_bridge_ip_addr_before = $_POST['bridge_ip_addr_before'];
$_bridge_ip_addr = $_POST['bridge_ip_addr'];
$_bridge_subnet_msk_before = $_POST['bridge_subnet_msk_before'];
$_bridge_subnet_msk = $_POST['bridge_subnet_msk'];
if( ($_bridge_ip_addr_before != $_bridge_ip_addr) || ($_bridge_subnet_msk_before != $_bridge_subnet_msk) )
{
    $query = "update basic_config set bridge_ip_addr=\"$_bridge_ip_addr\", bridge_subnet_msk=\"$_bridge_subnet_msk\"  where id=1 ";
    mysql_query($query, $db);
}

print "<meta HTTP-EQUIV=\"REFRESH\" content=\"0; url=bridge.php\">";
?>
