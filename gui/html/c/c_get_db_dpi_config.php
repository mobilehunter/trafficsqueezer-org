<?php
$query = "select
dpi_enable, 
dpi_dns_request_enable,
dpi_http_access_enable,
dpi_pop_enable
from dpi_config where id=1";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
 while($row = mysql_fetch_array($result))
 {
 	$dpi_enable = $row['dpi_enable'];
	$dpi_dns_request_enable = $row['dpi_dns_request_enable'];
	$dpi_http_access_enable = $row['dpi_http_access_enable'];
	$dpi_pop_enable = $row['dpi_pop_enable'];
 }
}
?>