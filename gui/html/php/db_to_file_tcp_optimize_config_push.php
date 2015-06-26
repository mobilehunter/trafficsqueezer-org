<?php
//Read the TCP optimize settings in DB and push into /proc files.

error_reporting(5);

$db = mysql_connect("localhost", "root", "welcome") or die ("Error connecting to database.");
mysql_select_db("aquarium", $db) or die ("Couldn't select the database.");
$query = "select 
tcp_timestamps,
tcp_sack,
tcp_dsack,
tcp_fack,
tcp_window_scaling,
ip_no_pmtu_disc,
tcp_ecn,
rmem_max,
rmem_default,
wmem_max,
wmem_default,
tcp_congestion_control
from tcp_optimize_config where id=1 ";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
	while($row = mysql_fetch_array($result))
 {
			$tcp_timestamps = $row['tcp_timestamps'];
			$tcp_sack = $row['tcp_sack'];
			$tcp_dsack = $row['tcp_dsack'];
			$tcp_fack = $row['tcp_fack'];
			$tcp_window_scaling = $row['tcp_window_scaling'];
			$ip_no_pmtu_disc = $row['ip_no_pmtu_disc'];
			$tcp_ecn = $row['tcp_ecn'];
			$rmem_max = $row['rmem_max'];
			$rmem_default = $row['rmem_default'];
			$wmem_max = $row['wmem_max'];
			$wmem_default = $row['wmem_default'];
			$tcp_congestion_control = $row['tcp_congestion_control'];
	}
}
mysql_close($db);

system("echo $tcp_timestamps > /proc/sys/net/ipv4/tcp_timestamps");
system("echo $tcp_sack > /proc/sys/net/ipv4/tcp_sack");
system("echo $tcp_dsack > /proc/sys/net/ipv4/tcp_dsack");
system("echo $tcp_fack > /proc/sys/net/ipv4/tcp_fack");
system("echo $tcp_window_scaling > /proc/sys/net/ipv4/tcp_window_scaling");
system("echo $ip_no_pmtu_disc > /proc/sys/net/ipv4/ip_no_pmtu_disc");
system("echo $tcp_ecn > /proc/sys/net/ipv4/tcp_ecn");
system("echo $tcp_congestion_control > /proc/sys/net/ipv4/tcp_congestion_control");
system("echo $rmem_max > /proc/sys/net/core/rmem_max");
system("echo $rmem_default > /proc/sys/net/core/rmem_default");
system("echo $wmem_max > /proc/sys/net/core/wmem_max");
system("echo $wmem_default > /proc/sys/net/core/wmem_default");

?>
