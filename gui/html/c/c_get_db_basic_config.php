<?php
$query = "select
mode,
coal_en,
coalescing_protocol_dns_enable,
ip_forward_nat_enable,
host_name,
qos_enabled, qos_wan_bandwidth,
qos_p0_bandwidth, qos_p1_bandwidth, qos_p2_bandwidth,
qos_p3_bandwidth, qos_p4_bandwidth,
filter_dns_enable,
bridge_ip_addr,
bridge_subnet_msk,
r_ip_ntwrk_machine_en
from basic_config where id=1";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
 while($row = mysql_fetch_array($result))
 {	$mode=$row['mode'];
	$coal_en = $row['coal_en'];
	$coalescing_protocol_dns_enable = $row['coalescing_protocol_dns_enable'];
	$ip_forward_nat_enable = $row['ip_forward_nat_enable'];

	$host_name = $row['host_name'];
	$qos_enabled = $row['qos_enabled'];
	$qos_wan_bandwidth = $row['qos_wan_bandwidth'];
	$qos_p0_bandwidth = $row['qos_p0_bandwidth'];
	$qos_p1_bandwidth = $row['qos_p1_bandwidth'];
	$qos_p2_bandwidth = $row['qos_p2_bandwidth'];
	$qos_p3_bandwidth = $row['qos_p3_bandwidth'];
	$qos_p4_bandwidth = $row['qos_p4_bandwidth'];
	$filter_dns_enable = $row['filter_dns_enable'];
	$bridge_ip_addr = $row['bridge_ip_addr'];
	$bridge_subnet_msk = $row['bridge_subnet_msk'];
	$r_ip_ntwrk_machine_en = $row['r_ip_ntwrk_machine_en'];
 }
}

?>