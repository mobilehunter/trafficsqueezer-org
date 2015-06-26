<?php include('c/c_check_login.php'); ?>
<html><body style="font-family:arial;font-size:10px;">
<?php error_reporting(5);
include("c/c_db_access.php"); include('c/c_bigpicture.php'); include("c/c_get_db_basic_config.php");
 
print "<div style=\"position:absolute;left:5;top:35;border:0;\">Remote IP-Subnet(s)/Machines</div>";
status_box_var($r_ip_ntwrk_machine_en, 156, 35);

function short_subnet_mask($subnet_msk)
{ $short_subnet_mask = 0;
  $subnet_msk_octets = split('\.', $subnet_msk);

  $n = $subnet_msk_octets[0];
  $n = ($n & 0x55555555) + (($n & 0xaaaaaaaa) >> 1);
  $n = ($n & 0x33333333) + (($n & 0xcccccccc) >> 2);
  $n = ($n & 0x0f0f0f0f) + (($n & 0xf0f0f0f0) >> 4);
  $n = ($n & 0x00ff00ff) + (($n & 0xff00ff00) >> 8);
  $n = ($n & 0x0000ffff) + (($n & 0xffff0000) >> 16);
  $short_subnet_mask += $n;

  $n = $subnet_msk_octets[1];
  $n = ($n & 0x55555555) + (($n & 0xaaaaaaaa) >> 1);
  $n = ($n & 0x33333333) + (($n & 0xcccccccc) >> 2);
  $n = ($n & 0x0f0f0f0f) + (($n & 0xf0f0f0f0) >> 4);
  $n = ($n & 0x00ff00ff) + (($n & 0xff00ff00) >> 8);
  $n = ($n & 0x0000ffff) + (($n & 0xffff0000) >> 16);
  $short_subnet_mask += $n;

  $n = $subnet_msk_octets[2];
  $n = ($n & 0x55555555) + (($n & 0xaaaaaaaa) >> 1);
  $n = ($n & 0x33333333) + (($n & 0xcccccccc) >> 2);
  $n = ($n & 0x0f0f0f0f) + (($n & 0xf0f0f0f0) >> 4);
  $n = ($n & 0x00ff00ff) + (($n & 0xff00ff00) >> 8);
  $n = ($n & 0x0000ffff) + (($n & 0xffff0000) >> 16);
  $short_subnet_mask += $n;

  $n = $subnet_msk_octets[3];
  $n = ($n & 0x55555555) + (($n & 0xaaaaaaaa) >> 1);
  $n = ($n & 0x33333333) + (($n & 0xcccccccc) >> 2);
  $n = ($n & 0x0f0f0f0f) + (($n & 0xf0f0f0f0) >> 4);
  $n = ($n & 0x00ff00ff) + (($n & 0xff00ff00) >> 8);
  $n = ($n & 0x0000ffff) + (($n & 0xffff0000) >> 16);
  $short_subnet_mask += $n;
  return $short_subnet_mask;
}

$top = 50;
print "<div style=\"position:absolute;left:5;top:0;border:0;\"><img src=\"i/cc/black/cloud_icon&32.png\"  width=32 \"></div>";
$query = "select type, network_id, subnet_msk from remote_subnet ";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
	while($row = mysql_fetch_array($result))
	{
		$network_id = $row['network_id'];
		$subnet_msk = $row['subnet_msk'];
		$short_subnet_mask = short_subnet_mask($subnet_msk);
     	print "<div style=\"position:absolute;left:5;top: $top;border:0;\"> $network_id/$short_subnet_mask </div>";
     	$top += 15;
	}
}

$top = 50;
print "<div style=\"position:absolute;left:150;top:0;border:0;\"><img src=\"i/cc/black/comp_icon&32.png\"  width=32 \"></div>";
$query = "select type, ip_addr from remote_ip_machine";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
	while($row = mysql_fetch_array($result))
	{
		$ip_addr = $row['ip_addr'];
	  	print "<div style=\"position:absolute;left:160;top: $top;border:0;\"> $ip_addr </div>";
		$top += 15;
	}
}
?></body></html>