<?php include("c/c_db_access.php"); include('c/c_g_var_set.php'); include("c/c_g_var_tcp_opt_set.php");
session_start(); error_reporting(5);

$mode = $_GET['mode'];

//Disable everything (initialize)
set_mode("MODE_NONE", $query, $db);
activate_router($query, $db); //disable (if not enabled)
activate_bridge($query, $db); //disable (if not enabled)

//unset ports
set_port_lan_name("none", $query, $db);
set_port_wan_name("none", $query, $db);

if($mode=="reset")
{ /* do nothing since it is reset above */
 	print "<meta HTTP-EQUIV=\"REFRESH\" content=\"0; url=w_finish.php\">";
}
else if($mode=="router")
{
	set_mode("MODE_ROUTER", $query, $db);
	redirect();
}
else if($mode=="bridge")
{
	set_mode("MODE_BRIDGE", $query, $db);
 	redirect();
}
else if($mode=="local-device")
{
	set_mode("MODE_LOCAL", $query, $db);
	print "<meta HTTP-EQUIV=\"REFRESH\" content=\"0; url=w_wan_port.php\">";
}
else if($mode=="local-device-router") //router + local-device-mode (such as when Squid enabled and so on).
{
 	set_mode("MODE_ROUTER_LOCAL", $query, $db);
 	redirect();
}
else if($mode=="simulation")
{
 	set_mode("MODE_SIMULATE", $query, $db);
 	print "<meta HTTP-EQUIV=\"REFRESH\" content=\"0; url=w_wan_port_simulation.php\">";
}
else 
{ redirect(); }

function redirect()
{ print "<meta HTTP-EQUIV=\"REFRESH\" content=\"0; url=w_lan_port.php\">"; }
?>