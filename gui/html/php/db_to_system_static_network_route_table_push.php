<?php
//Read the Static IP route (table) in DB and push into /proc files.

error_reporting(5);

$db = mysql_connect("localhost", "root", "welcome") or die ("Error connecting to database.");
mysql_select_db("aquarium", $db) or die ("Couldn't select the database.");
$query = "select type, network_id, subnet_msk, gateway, gateway_port from static_network_route_table where type=\"ipv4\" ";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
	while($row = mysql_fetch_array($result))
	{
			$network_id = $row['network_id'];
			$subnet_msk = $row['subnet_msk'];
			$gateway = $row['gateway'];
			$gateway_port = $row['gateway_port'];
			system("route add -net $network_id netmask $subnet_msk gw $gateway $gateway_port ");
	}
}
mysql_close($db);

?>
