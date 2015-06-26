<style type="text/css">
table.grid_style {border-width:1px;border-spacing:2px;border-style:ridge;border-color:#B6B6B6;border-collapse:collapse;background-color:white;}
table.grid_style th {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:10px;}
table.grid_style td {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:10px;}
#table_top_heading {background-color:gray;font-weight:bold;color:white;text-decoration:none;font-size:10px;}
</style>
<table class="grid_style" width="650">
<tr><td id="table_top_heading">Name</td><td id="table_top_heading">IP Addr</td><td id="table_top_heading">Subnet Mask</td>
<td id="table_top_heading">MAC</td><td id="table_top_heading">Direction</td></tr>
<?php include("c_db_access.php");
$_lan_port="None"; $_wan_port="None";
 $query = "select name, ip_addr, subnet_msk, mac, direction from port_list";
	$result=mysql_query($query, $db);
	if(mysql_num_rows($result) > 0)
	{	while($row = mysql_fetch_array($result))
	 	{
	 	$name = $row['name'];
		$ip_addr = $row['ip_addr'];
		$subnet_msk = $row['subnet_msk'];
		$mac = $row['mac'];
		$direction = $row['direction'];
		
		if($direction=="LAN" || $direction=="WAN") $background="style=\"background-color:#F0F0F0;\""; else $background="";  
		
  		print "<tr>";
      print "<td $background >$name</td><td $background >$ip_addr</td><td $background >$subnet_msk</td><td $background >$mac</td>";
      print "<td $background >";
      print "<center><form method=\"POST\" action=\"ports_bknd.php\">";
 		print "<input type=\"hidden\" id=\"port_name\" name=\"port_name\" value=\"$name\" />";
      print "<select style=\"border:none;font-size:10px;\" name=\"port_direction\" id=\"port_direction\">";
    	if($direction==NULL) { print "<option value=\"None\" selected>None</option>"; } else { print "<option value=\"None\" >None</option>"; }
    	if($direction=="LAN") { print "<option value=\"LAN\" selected>LAN</option>"; } else { print "<option value=\"LAN\">LAN</option>"; }
    	if($direction=="WAN") { print "<option value=\"WAN\" selected>WAN</option>"; } else { print "<option value=\"WAN\">WAN</option>"; }
    	print "</select> &nbsp;&nbsp;";
      print "<input title=\"Save Settings ?\" type=\"submit\" name=\"submit_ok\" value=\"Save\" style=\"border:0;background-color:#ff5c00;color:white;font-weight:bold;font-size:11px;\" />";
      print "</form></td>";
      print "</tr>";
	 	}
	}
?>
</table>
<br><br>