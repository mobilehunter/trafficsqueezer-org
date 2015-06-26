<?php  //Read the DB and push this configuration into kernel via "io" /proc file

$proc_io_file = "/proc/trafficsqueezer/io"; error_reporting(5); 
include("/var/www/html/c/c_db_access.php"); include('/var/www/html/c/c_g_var_set.php');
include("/var/www/html/c/c_get_db_port_config.php");
include("/var/www/html/c/c_get_db_basic_config.php");
include("/var/www/html/c/c_get_db_tcp_optimize_config.php");

set_port_lan_name($port_lan_name, $query, $db);
set_port_wan_name($port_wan_name, $query, $db); 

set_mode($mode, $query, $db);
if($mode=="MODE_ROUTER"||$mode=="MODE_ROUTER_LOCAL") activate_router($query, $db);
else if($mode=="MODE_BRIDGE") activate_bridge($query, $db);

set_r_ip_ntwrk_machine_en($r_ip_ntwrk_machine_en, $query, $db);

$query = "select type, network_id, subnet_msk from remote_subnet ";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
	while($row = mysql_fetch_array($result))
	{
		$network_id = $row['network_id'];
		$subnet_msk = $row['subnet_msk'];
		set_add_r_ip_ntwrk_list_network_id($network_id, $subnet_msk, $query, $db);
	}
}

$query = "select type, ip_addr from remote_ip_machine";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
	while($row = mysql_fetch_array($result))
	{
		$ip_addr = $row['ip_addr'];
	  	set_add_r_ip_machine_list($ip_addr, $query, $db);
	}
}

set_tcp_timestamps($tcp_timestamps, $query, $db);
set_tcp_sack($tcp_sack, $query, $db);
set_tcp_dsack($tcp_dsack, $query, $db);
set_tcp_fack($tcp_fack, $query, $db);
set_tcp_autocorking($tcp_autocorking, $query, $db);
set_tcp_window_scaling($tcp_window_scaling, $query, $db);
set_ip_no_pmtu_disc($ip_no_pmtu_disc, $query, $db);
set_tcp_congestion_control($tcp_congestion_control, $query, $db);
set_tcp_ecn($tcp_ecn, $query, $db);
set_rmem_max($rmem_max, $query, $db);
set_rmem_default($rmem_default, $query, $db);
set_wmem_max($wmem_max, $query, $db);
set_wmem_default($wmem_default, $query, $db);

?>