<style type="text/css">
table.grid_style {border-width:1px;border-spacing:2px;border-style:ridge;border-color:#B6B6B6;border-collapse:collapse;background-color:white;}
table.grid_style th {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:10px;}
table.grid_style td {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:10px;}
#table_top_heading {background-color:gray;font-weight:bold;color:white;text-decoration:none;font-size:10px;}
</style>

<?php include('c/c_db_access.php'); include('c/c_get_db_basic_config.php');
print '<table border="0" width="300">';
print "<tr><td>Remote IP Subnet(s)/Machine(s)</td><td>";
print "<form method=\"POST\" action=\"set_remote_bknd.php\">";                
print "<input type=\"hidden\" id=\"r_ip_ntwrk_machine_en_before\" name=\"r_ip_ntwrk_machine_en_before\" value=\"$r_ip_ntwrk_machine_en\" >";
if($r_ip_ntwrk_machine_en=="1") $checked = "checked"; else $checked = "";
print "<input type=\"checkbox\" style=\"border: 0;\"  name=\"r_ip_ntwrk_machine_en\"  id=\"r_ip_ntwrk_machine_en\" value=\"1\" $checked />";
print "&nbsp;&nbsp;<input title=\"Save Settings ?\" type=\"submit\" name=\"submit_ok\" value=\"Save\" style=\"border:0;background-color:#ff5c00;color:white;font-weight:bold;font-size:11px;\" />";
print "</td></tr>";
print "</table>";
print "</form>";

$query = "select count(*) remote_subnet_count from remote_subnet where type=\"ipv4\" ";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
	while($row = mysql_fetch_array($result))
	{	$remote_subnet_count=$row['remote_subnet_count'];
	}
}

if($remote_subnet_count)
{
	print "<br>Remote Subnet List Configuration<br>";
	print "<table class=\"grid_style\" width=\"500\">";
	print "<tr><th id=\"table_top_heading\">Network-ID</th><th id=\"table_top_heading\">Subnet Mask</th><th id=\"table_top_heading\"></th></tr>";
	$query = "select type, network_id, subnet_msk from remote_subnet where type=\"ipv4\" ";
	$result=mysql_query($query, $db);
	if(mysql_num_rows($result) > 0)
	{
		while($row = mysql_fetch_array($result))
		{	$network_id=$row['network_id'];
			$subnet_msk=$row['subnet_msk'];
     		print "<tr><td width=\"160\" style=\"color:#333333;\" align=middle>$network_id</td>";
     		print "<td width=\"160\" style=\"color:#333333;\" align=middle>$subnet_msk</td>";
     		print "<td width=\"175\" align=center >";
  	  		print "<form method=\"POST\" action=\"set_remote_bknd.php\">";
  	  		print "<input type=\"hidden\" id=\"operation\" name=\"operation\" value=\"remove_subnet\" >";
  	  		print "<input type=\"hidden\" id=\"network_id\" name=\"network_id\" value=\"$network_id\" >";
     		print "<input title=\"Remove IP Address ?\" type=\"submit\" name=\"submit_ok\" value=\"Remove\" style=\"border:0;background-color:#ff5c00;color:white;font-weight:bold;font-size:11px;\" />";
     		print "</form>";
     		print "</td>";
     		print "</tr>";
		}
	}
	print "</table>";
}

print "<br><br>";
print "Add New Remote IP Subnet: ";
print "<form method=\"POST\" action=\"set_remote_bknd.php\">";
print "<input type=\"hidden\" id=\"operation\" name=\"operation\" value=\"add_subnet\" >";
print "<table  class=\"grid_style\" width=\"500\">";
print "<tr>";
print "<td width=\"160\" align=><input style=\"width:160px;border:1;font-size:11px;\"  type=\"text\"  name=\"network_id\" value=\"<network id>\" onClick=\"if (this.value == '<network id>') {this.style.color='#000000'; this.value=''}\" onBlur=\"if (this.value == '') {this.style.color='#000000'; this.value='<network id>'}\" /></td>";
print "<td width=\"160\" align=><input style=\"width:160px;border:1;font-size:11px;\"  type=\"text\"  name=\"subnet_msk\" value=\"<subnet mask>\" onClick=\"if (this.value == '<subnet mask>') {this.style.color='#000000'; this.value=''}\" onBlur=\"if (this.value == '') {this.style.color='#000000'; this.value='<subnet mask>'}\" /></td>";
print "<td width=\"175\" align=center >&nbsp;&nbsp;<input title=\"Add new subnet ?\" type=\"submit\" name=\"submit_ok\" value=\"Add\" style=\"border:0;background-color:#91bd09;color:white;font-weight:bold;font-size:11px;\" /></td>";
print "</tr>";
print "</table>";
print "</form>";

print "<br><br>";

$query = "select count(*) remote_ip_machine_count from remote_ip_machine where type=\"ipv4\" ";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
	while($row = mysql_fetch_array($result))
	{	$remote_ip_machine_count=$row['remote_ip_machine_count'];
	}
}

if($remote_ip_machine_count)
{
	print "Remote Machine List Configuration<br>";
	print "<table class=\"grid_style\" width=\"500\">";
	print "<tr><th id=\"table_top_heading\">IP Address</th><th id=\"table_top_heading\"></th></tr>";
	$query = "select type, ip_addr from remote_ip_machine where type=\"ipv4\" ";
	$result=mysql_query($query, $db);
	if(mysql_num_rows($result) > 0)
	{
 		while($row = mysql_fetch_array($result))
 		{
			$ip_addr = $row['ip_addr'];
  			print "<tr>";
  			print "<td width=\"160\" style=\"color:#333333;\" align=middle>$ip_addr</td>";
  			print "<td width=\"175\" align=center >";
  			print "<form method=\"POST\" action=\"set_remote_bknd.php\">";
  			print "<input type=\"hidden\" id=\"ip_addr\" name=\"ip_addr\" value=\"$ip_addr\" >";
  			print "<input type=\"hidden\" id=\"operation\" name=\"operation\" value=\"remove_machine\" >";
  			print "<input title=\"Remove IP Address ?\" type=\"submit\" name=\"submit_ok\" value=\"Remove\" style=\"border:0;background-color:#ff5c00;color:white;font-weight:bold;font-size:11px;\" />";
  			print "</form>";
  			print "</td>";
  			print "</tr>";
 		}
	}
	print "</table>";
}

print "<br><br>";
print "Add New Remote Machine:";
print "<form method=\"POST\" action=\"set_remote_bknd.php\">";
print "<input type=\"hidden\" id=\"operation\" name=\"operation\" value=\"add_machine\" >";
print "<table class=\"grid_style\" width=\"500\">";
print "<tr>";
print "<td width=\"160\" ><input style=\"width:160px;border:1;font-size:11px;\" type=\"text\" name=\"ip_addr\" value=\"<IP Address>\" onClick=\"if (this.value == '<IP Address>') {this.style.color='#000000'; this.value=''}\" onBlur=\"if (this.value == '') {this.style.color='#000000'; this.value='<IP Address>'}\"  /></td>";
print "<td width=\"175\" align=center>&nbsp;&nbsp;<input title=\"Add new subnet ?\" type=\"submit\" name=\"submit_ok\" value=\"Add\" style=\"border:0;background-color:#91bd09;color:white;font-weight:bold;font-size:11px;\" /></td>";
print "</tr>";
print "</table>";
print "</form>";

?>
