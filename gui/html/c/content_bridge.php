<style type="text/css">
table.grid_style {border-width:1px;border-spacing:2px;border-style:ridge;border-color:#B6B6B6;border-collapse:collapse;background-color:white;}
table.grid_style th {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:10px;}
table.grid_style td {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:10px;}
#table_top_heading {background-color:gray;font-weight:bold;color:white;text-decoration:none;font-size:10px;}
</style>
<?php include('c/c_db_access.php'); include('c/c_get_db_basic_config.php');

print "<form method=\"POST\" action=\"bridge_bknd.php\">";
print "<input type=\"hidden\" id=\"bridge_ip_addr_before\" name=\"bridge_ip_addr_before\" value=\"$bridge_ip_addr\" >";
print "<input type=\"hidden\" id=\"bridge_subnet_msk_before\" name=\"bridge_subnet_msk_before\" value=\"$bridge_subnet_msk\" >";    
print "<table  id=\"basic_font_style_10px\" border=0 width=\"550\">";
print "<tr><td width=\"70\"> Port Address</td><td width=\"380\"> IP Address:";
print "<input style=\"width:120px;border:1;font-size:11px;\"  type=\"text\"  name=\"bridge_ip_addr\" value=\"$bridge_ip_addr\" onClick=\"if (this.value == '$bridge_ip_addr') {this.style.color='#000000'; this.value='$bridge_ip_addr'}\" onBlur=\"if (this.value == '$bridge_ip_addr') {this.style.color='#000000'; this.value='$bridge_ip_addr'}\" />";
print " - Subnet Mask:";
print "<input style=\"width:120px;border:1;font-size:11px;\"  type=\"text\"  name=\"bridge_subnet_msk\" value=\"$bridge_subnet_msk\" onClick=\"if (this.value == '$bridge_subnet_msk') {this.style.color='#000000'; this.value='$bridge_subnet_msk'}\" onBlur=\"if (this.value == '$bridge_subnet_msk') {this.style.color='#000000'; this.value='$bridge_subnet_msk'}\" />";
print "<tr><td><br></td></tr>";
print "<tr><td valign=bottom width=\"70\">";
print "<input title=\"Save bridge settings ?\" type=\"submit\" name=\"submit_ok\" value=\"Save\" style=\"border:0;background-color:#ff5c00;color:white;font-weight:bold;font-size:11px;\" /></td>";
print "<td width=\"250\"></td></tr>";
print "</table>";
print "</form>";

?>
<br><br>