<style type="text/css">
table.grid_style {border-width:1px;border-spacing:2px;border-style:ridge;border-color:#B6B6B6;border-collapse:collapse;background-color:white;}
table.grid_style th {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:10px;}
table.grid_style td {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:10px;}
#table_top_heading {background-color:gray;font-weight:bold;color:white;text-decoration:none;font-size:10px;}
</style>
<?php include('c/c_db_access.php'); include('c/c_get_db_basic_config.php');
print '<table border="0" width="640">';
print '<tr><td>Mode</td><td width="580">';
$disabled="disabled=disabled";
if($mode=="MODE_NONE") $checked="checked"; else $checked="";
print "<input $readonly $disabled type=\"radio\" id=\"mode\" name=\"mode\" value=\"NONE\" $checked />None&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
if($mode=="MODE_ROUTER") $checked="checked"; else $checked="";
print "<input  $readonly $disabled type=\"radio\" id=\"mode_router\" name=\"mode\" value=\"MODE_ROUTER\" $checked />Router&nbsp;&nbsp;&nbsp;&nbsp;";
if($mode=="MODE_BRIDGE") $checked="checked"; else $checked="";
print "<input  $readonly  $disabled type=\"radio\" id=\"mode_bridge\" name=\"mode\" value=\"MODE_BRIDGE\" $checked />Bridge&nbsp;&nbsp;&nbsp;&nbsp;";
if($mode=="MODE_LOCAL") $checked="checked"; else $checked="";
print "<input  $readonly $disabled type=\"radio\" id=\"mode_local\" name=\"mode\" value=\"MODE_LOCAL\" $checked />Local-device&nbsp;&nbsp;&nbsp;&nbsp;";
if($mode=="MODE_ROUTER_LOCAL") $checked="checked"; else $checked="";
print "<input  $readonly $disabled type=\"radio\" id=\"mode_router_local\" name=\"mode\" value=\"MODE_ROUTER_LOCAL\" $checked />Router Local-device&nbsp;&nbsp;&nbsp;&nbsp;";
if($mode=="MODE_SIMULATE") $checked="checked"; else $checked="";
print "<input  $readonly $disabled type=\"radio\" id=\"mode_simulate\" name=\"mode\" value=\"MODE_SIMULATE\" $checked />Simulate&nbsp;&nbsp;&nbsp;&nbsp;";
print "</td></tr>";
print "<tr><td><br><b>Optimization</b></td></tr>";
print "<tr><td>Compression</td><td><input $readonly type=\"checkbox\" disabled name=\"compress_enabled\" id=\"compress_enabled\" value=\"1\" checked /></td></tr>";
print "<tr><td>Templating</td><td><input readonly=readonly type=\"checkbox\" disabled=disabled  id=\"template_enable\" name=\"template_enable\" value=\"1\" checked /></td></tr>";
print "<tr><td>Coalescing</td><td><input readonly=readonly type=\"checkbox\" disabled=disabled  id=\"coal_en\" name=\"coal_en\" value=\"1\" /></td></tr>";
print "<tr><td><br></td></tr>";
print "</table></center>";
?>
<br><br>