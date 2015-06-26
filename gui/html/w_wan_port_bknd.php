<?php include("c/c_db_access.php"); include('c/c_g_var_set.php'); include("c/c_get_db_basic_config.php"); session_start(); error_reporting(5);

$squid = $_GET['squid'];

set_port_wan_name($_GET['port'], $query, $db);
	 
//no remote ip subnet/machine settings since it is 100% testing.
set_r_ip_ntwrk_machine_en(0, $query, $db);
  	 
//now assuming both ports are set, if so check if bridging/routing is enabled, if so activate, else deactivate!
if($mode=="MODE_ROUTER"||$mode=="MODE_ROUTER_LOCAL") activate_router($query, $db);
else if($mode=="MODE_BRIDGE") activate_bridge($query, $db);


print "<meta HTTP-EQUIV=\"REFRESH\" content=\"0; url=w_finish.php\">";
?>