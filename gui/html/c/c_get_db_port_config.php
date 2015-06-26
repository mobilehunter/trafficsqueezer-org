<?php
$query = "select
port_lan_name, 
port_wan_name,
port_lan_ip_addr,
port_wan_ip_addr
from port_config where id=1";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
 while($row = mysql_fetch_array($result))
 {
 	$port_lan_name = $row['port_lan_name'];
	$port_wan_name = $row['port_wan_name'];
	$port_lan_ip_addr = $row['port_lan_ip_addr'];
	$port_wan_ip_addr = $row['port_wan_ip_addr'];
 }
}
?>