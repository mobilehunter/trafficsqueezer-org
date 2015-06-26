<style type="text/css">
table.grid_style {border-width:1px;border-spacing:2px;border-style:ridge;border-color:#B6B6B6;border-collapse:collapse;background-color:white;}
table.grid_style th {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:10px;}
table.grid_style td {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:10px;}
#table_top_heading {background-color:gray;font-weight:bold;color:white;text-decoration:none;font-size:10px;}
</style>

<table summary="sidebar buttons" width="500" cellspacing=6 cellpadding=0  style="font-family:arial;color:gray;font-size:11px;">
<td align=middle ><form method="POST" action="w_device_type_bknd.php?mode=reset">
<input title="Reset Device type ?" type="submit" name="submit_ok" value="Reset" style="border:0;background-color:#B6B6B6;color:white;font-weight:bold;font-size:11px;" />
</form></td>
<td align=middle ><form method="POST" action="w_device_type_bknd.php?mode=local-device">
<input title="Local Device / Server ?" type="submit" name="submit_ok" value="Device/Server" style="border:0;background-color:#91bd09;color:white;font-weight:bold;font-size:11px;" />
</form></td>
<td align=middle ><form method="POST" action="w_device_type_bknd.php?mode=router">
<input title="L3 Router Mode ?" type="submit" name="submit_ok" value="Router" style="border:0;background-color:#91bd09;color:white;font-weight:bold;font-size:11px;" />
</form></td>
<td align=middle ><form method="POST" action="w_device_type_bknd.php?mode=bridge">
<input title="L2 Bridge Mode ?" type="submit" name="submit_ok" value="Bridge" style="border:0;background-color:#91bd09;color:white;font-weight:bold;font-size:11px;" />
</form></td>
<td align=middle ><form method="POST" action="w_device_type_bknd.php?mode=simulation">
<input title="Simulation ?" type="submit" name="submit_ok" value="Simulation" style="border:0;background-color:#ff5c00;color:white;font-weight:bold;font-size:11px;" />
</form></td>
<td align=middle ><form method="POST" action="w_lan_port.php">
<input title="Skip this ?" type="submit" name="submit_ok" value="Skip" style="border:0;background-color:#B6B6B6;color:white;font-weight:bold;font-size:11px;" />
</form></td>
</tr>
</table>
<br>
<table summary="sidebar buttons" width="240" cellspacing=6 cellpadding=0  style="font-family:arial;color:gray;font-size:11px;">
<tr><td width=145 align=middle ></td>
<td align=middle ><form method="POST" action="w_device_type_bknd.php?mode=local-device-router">
<input title="L3 Router as well Local Device/Server ?" type="submit" name="submit_ok" value="Router & Device/Server" style="border:0;background-color:#91bd09;color:white;font-weight:bold;font-size:11px;" />
</form></td>
</tr>
</table>


<br><br>