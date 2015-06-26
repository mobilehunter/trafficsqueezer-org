<?php include('c/c_check_login.php'); ?>
<html><head><?php error_reporting(5); include("c/c_db_access.php");
include("c/c_get_db_basic_config.php");
include("c/c_get_db_dpi_config.php");
include("c/c_get_db_port_config.php");
include('c/c_bigpicture.php');
?>
</head><body style="font-family:arial;font-size:10px;">
<?php
print "<div style=\"position:absolute;left:25;top:38;border:0;\"><img src=\"i/bigpicture_inline.png\" ></div>";
$counter = 0;
$lan_left = 940;

print "<div style=\"position:absolute;left:586;top:95;border:0;\">$port_wan_name</div>";
print "<div style=\"position:absolute;left:800;top:95;border:0;\">$port_lan_name</div>";
print "<iframe style=\"width:280px;border:0;height:300;left:0;top:120;position:absolute;\" scrolling=\"no\" src=\"bigpicture_inline_remote.php\"></iframe>";

print "<div style=\"position:absolute;left:360;top:160;border:0;\">Mode</div>";
if($mode=="MODE_NONE") $mode="None";
else if($mode=="MODE_ROUTER") $mode="Router";
else if($mode=="MODE_BRIDGE") $mode="Bridge";
else if($mode=="MODE_ROUTER_LOCAL") $mode="Router & Local-Device";
else if($mode=="MODE_LOCAL") $mode="Local-Device";
else if($mode=="MODE_SIMULATE") $mode="Simulation";
print "<div style=\"position:absolute;left:445;top:160;border:0;\">$mode</div>";
 
print "<div style=\"position: absolute;left:360;top:183;border:0;\">Compression</div>";
status_box(445, 183, "green");

print "<div style=\"position: absolute;left:360;top:206;border:0;\">Coalescing</div>";
status_box_var($coal_en, 445, 206);
          
print "<div style=\"position:absolute;left:360;top:229;border:0;\">Templating</div>";
status_box(445, 229, "green");
       
print "<div style=\"position: absolute;left:360;top:252;border:0;\">DPI</div>";
if($dpi_enable=="1") { status_box(445, 252, "green"); } else { status_box(445, 252, "red"); }

print "<div style=\"position: absolute;left:360;top:275;border:0;\">NAT</div>";
if($ip_forward_nat_enable=="1") { status_box(445, 275, "green"); } else { status_box(445, 275, "red"); }

print "<div style=\"position: absolute;left:360;top:298;border:0;\">DNS Filter</div>";
if($dns_filter_enable=="1") { status_box(445, 298, "green"); } else { status_box(445, 298, "red"); }           

 $dns_top = 272;

if($buf!=NULL)
{
     foreach (preg_split("/(\r?\n)/", $buf) as $line)
     {
         if ($line != NULL)
         {
           	if($dns_filter_enable == "1")
           	{
             	print "<div style=\"position: absolute; left: 1148; top: $dns_top;border: 0;font-size: 11px;font-family: Arial;\">$line</div>";
            }
          }
    	$dns_top += 10;
  	 }       
}
          
?></body></html>