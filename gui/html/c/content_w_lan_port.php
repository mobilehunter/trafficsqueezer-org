<style type="text/css">
table.grid_style {border-width:1px;border-spacing:2px;border-style:ridge;border-color:#B6B6B6;border-collapse:collapse;background-color:white;}
table.grid_style th {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:10px;}
table.grid_style td {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:10px;}
#table_top_heading {background-color:gray;font-weight:bold;color:white;text-decoration:none;font-size:10px;}
</style>

<table summary="sidebar buttons" width="400" cellspacing=6 cellpadding=0  style="font-family:arial;color:gray;font-size:11px;">
<tr>
<td align=middle ><form method="POST" action="w_lan_port_bknd.php?port=none">
<input title="Remove LAN Port ?" type="submit" name="submit_ok" value="None" style="border:0;background-color:#B6B6B6;color:white;font-weight:bold;font-size:11px;" />
</form></td>
</tr>
<tr>
<?php include("c_db_access.php");
	$count=1;
	$query = "select name, direction from port_list";
	$result=mysql_query($query, $db);
	if(mysql_num_rows($result) > 0)
	{
	  while($row = mysql_fetch_array($result))
	  {
		 $direction = $row['direction'];
		 $name = $row['name'];
		 if($direction=="None" || $direction=="") $direction="";
		 else $direction="[$direction]";
		 print "</td>";
		 print "<td align=middle ><form method=\"POST\" action=\"w_lan_port_bknd.php?port=$name\">";
		 print "<input title=\"\" type=\"submit\" name=\"submit_ok\" value=\"$name $direction\" style=\"border:0;background-color:#91bd09;color:white;font-weight:bold;font-size:11px;\" />";
		 print "</form></td>";
		 if($count%5==0) print "</tr><tr>";
		 $count++;
	 	}
	}
?>
</tr>
<tr>
<td align=middle ><form method="POST" action="w_wan_port.php">
<input title="Skip this ?" type="submit" name="submit_ok" value="Skip" style="border:0;background-color:#B6B6B6;color:white;font-weight:bold;font-size:11px;" />
</form></td></tr>
</table>
<br><br>