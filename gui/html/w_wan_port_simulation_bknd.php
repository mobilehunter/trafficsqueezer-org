<?php include("c/c_db_access.php"); include('c/c_g_var_set.php'); session_start(); error_reporting(5);

//set wan port (to real port)
set_port_wan_name($_GET['port'], $query, $db);
	    
//set lan port (to none)
set_port_lan_name("none", $query, $db);

//no remote ip subnet/machine settings since it is 100% testing.
set_r_ip_ntwrk_machine_en(0, $query, $db);
    	 
//no dns block.
//execute_generic_command_set("l7filter dns block-domain disable");


print "<meta HTTP-EQUIV=\"REFRESH\" content=\"0; url=w_finish.php\">";
?>