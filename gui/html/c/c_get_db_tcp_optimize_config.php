<?php

$query = "select 
tcp_timestamps,
tcp_sack,
tcp_dsack,
tcp_fack,
tcp_autocorking,
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
			$tcp_autocorking = $row['tcp_autocorking'];
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
?>
