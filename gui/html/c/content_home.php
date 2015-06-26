<style type="text/css">
table.grid_style {border-width:1px;border-spacing:2px;border-style:ridge;border-color:#B6B6B6;border-collapse:collapse;background-color:white;}
table.grid_style th {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:10px;}
#td {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:10px;}
#table_top_heading {background-color:gray;font-weight:bold;color:white;text-decoration:none;font-size:10px;}

#flotcontainerlan { width:250px;height:100px;background-color:white;}
#flotcontainerwan { width:250px;height:100px;background-color:white;}
#flotcontainerlanpkts { width:240px;height:100px;background-color:white;}
#flotcontainerwanpkts { width:240px;height:100px;background-color:white;}
#l_in_pktsizes { width:220px;height:100px;background-color:white;}
#l_out_pktsizes { width:220px;height:100px;background-color:white;}
#w_in_pktsizes { width:220px;height:100px;background-color:white;}
#w_out_pktsizes { width:220px;height:100px;background-color:white;}
</style>

<script src="c/flot/jquery.js"></script>
<script src="c/flot/excanvas.js"></script>
<script src="c/flot/jquery.flot.js"></script>
<script src="c/flot/jquery.flot.pie.js"></script>

<?php include("c_db_access.php");
function convert_to_mb_gb($value,$option)
{
	$gb = 1024;
	$tb = $gb*1024;
	$pb = $tb*1024;
	if($option==" GB")
	{
		$value=$value/$gb;
		$value = round($value,2);
	}
	else if($option==" TB")
	{
		$value=$value/$tb;
		$value = round($value,2);
	}
	else if($option==" PB")
	{
		$value=$value/$pb;
		$value = round($value,2);
	}
	else
	{
		$value = round($value,2);
	}
	
	return $value;
}



$query = "select (sum(lan_rx)/1024) lan_rx, (sum(lan_tx)/1024) lan_tx, (sum(wan_rx)/1024) wan_rx, (sum(wan_tx)/1024) wan_tx from stats_overall";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
	while($row = mysql_fetch_array($result))
 {
 	  	
	  $lan_rx = $row['lan_rx'];
	  $lan_tx = $row['lan_tx'];
	  $wan_rx = $row['wan_rx'];
	  $wan_tx = $row['wan_tx'];
 }
}

$query = "select (sum(lan_bytes_saved)/1024) total_lan_bytes_saved, (sum(wan_bytes_saved)/1024) total_wan_bytes_saved from stats_overall";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
 while($row = mysql_fetch_array($result))
 {
	  $total_lan_bytes_saved = $row['total_lan_bytes_saved'];
	  $total_wan_bytes_saved = $row['total_wan_bytes_saved'];
 }
}

$format = "";
$gb = 1024;
$tb = $gb*1024;
$pb = $tb*1024;
if(max($lan_rx, $lan_tx, $wan_rx, $wan_tx)>$gb) { $format=" GB"; }
else if(max($lan_rx, $lan_tx, $wan_rx, $wan_tx)>$tb) { $format=" TB"; }
else if(max($lan_rx, $lan_tx, $wan_rx, $wan_tx)>$pb) { $format=" PB"; }
else { $format=" MB"; }

$lan_rx = convert_to_mb_gb($lan_rx, $format);
$lan_tx = convert_to_mb_gb($lan_tx, $format);
$wan_rx = convert_to_mb_gb($wan_rx, $format);
$wan_tx = convert_to_mb_gb($wan_tx, $format);

$total_lan_bytes_saved = convert_to_mb_gb($total_lan_bytes_saved, $format);
$total_wan_bytes_saved = convert_to_mb_gb($total_wan_bytes_saved, $format);

$total_lan_bytes_saved_pct = $total_lan_bytes_saved/$lan_rx*100;
$total_lan_bytes_saved_pct = round($total_lan_bytes_saved_pct,1);
$total_wan_bytes_saved_pct = $total_wan_bytes_saved/$wan_tx*100;
$total_wan_bytes_saved_pct = round($total_wan_bytes_saved_pct,1);
?>

<?php

$color_red = 'color: "rgba(255,102,110,0.8)"';
$color_blue = 'color: "rgba(170,214,252,0.8)"';
$color_green = 'color: "rgba(28,203,91,0.8)"';
$color_yellow = 'color: "rgba(239,201,43,0.8)"';
$color_gray = 'color: "rgba(157,157,157,0.8)"';
$color_black = 'color: "rgba(0,0,0,0.8)"';

print '<script type="text/javascript">';
$saved = "Savings $total_lan_bytes_saved $format ($total_lan_bytes_saved_pct %)";
$sent = "Sent $lan_tx $format";
print '$(function () { 
    var lan_data = [
        {label: "'.$saved.'", '.$color_red.', data:'.$total_lan_bytes_saved.'},
        {label: "'.$sent.'", '.$color_blue.', data: '.$lan_tx.'}
    ];';
    
$saved = "Savings $total_wan_bytes_saved $format ($total_wan_bytes_saved_pct %)";
$received = "Received $wan_rx $format";
print 'var wan_data = [
        {label: "'.$saved.'", '.$color_red.', data:'.$total_wan_bytes_saved.'},
        {label: "'.$received.'", '.$color_blue.', data: '.$wan_rx.'}
    ];';
    
print 'var options = { series: { pie: {show: true, innerRadius: 0.3,radius:44} },legend: {position:"se",borderColor:"#ffffff"}   };
    $.plot($("#flotcontainerlan"), lan_data, options);
    $.plot($("#flotcontainerwan"), wan_data, options);
      
});';
print '</script>';
?>

<?php
$lan_rx .= $format;
$lan_tx .= $format;
$wan_rx .= $format;
$wan_tx .= $format;
$total_lan_bytes_saved .= $format;
$total_wan_bytes_saved .= $format;
?>

<table class="grid_style" width="550">
<tr><td id="table_top_heading">&nbsp;&nbsp;&nbsp;LAN -> WAN</td><td id="table_top_heading">&nbsp;&nbsp;&nbsp;WAN -> LAN</td></tr>
<tr><td><div id="flotcontainerlan"></div></td><td><div id="flotcontainerwan"></div></td></tr>
<?php
print "<tr><td id=\"td\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Received $lan_rx (Total)</td><td id=\"td\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Sent $wan_tx (Total)</td></tr>";
?>
</table><br>




<br><b>IP Protocol Packet Analysis: <i>(in Thousands)</i></b><br>
<table class="grid_style" width="550">
<tr><td id="table_top_heading">&nbsp;&nbsp;&nbsp;LAN -> WAN</td><td id="table_top_heading">&nbsp;&nbsp;&nbsp;WAN -> LAN</td></tr>
<?php
$query = "select (sum(l_tcp_pkt_cnt)/1000) l_tcp_pkt_cnt, (sum(l_udp_pkt_cnt)/1000) l_udp_pkt_cnt, 
			(sum(l_icmp_pkt_cnt)/1000) l_icmp_pkt_cnt, (sum(l_sctp_pkt_cnt)/1000) l_sctp_pkt_cnt,
			(sum(l_others_pkt_cnt)/1000) l_others_pkt_cnt, 
			(sum(w_tcp_pkt_cnt)/1000) w_tcp_pkt_cnt, (sum(w_udp_pkt_cnt)/1000) w_udp_pkt_cnt, 
			(sum(w_icmp_pkt_cnt)/1000) w_icmp_pkt_cnt, (sum(w_sctp_pkt_cnt)/1000) w_sctp_pkt_cnt,
			(sum(w_others_pkt_cnt)/1000) w_others_pkt_cnt 
 from stats_ip_proto";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
	while($row = mysql_fetch_array($result))
 {
 	  	
	  $l_tcp_pkt_cnt = round($row['l_tcp_pkt_cnt'],0);
	  $l_udp_pkt_cnt = round($row['l_udp_pkt_cnt'],0);
	  $l_icmp_pkt_cnt = round($row['l_icmp_pkt_cnt'],0);
	  $l_sctp_pkt_cnt = round($row['l_sctp_pkt_cnt'],0);
	  $l_others_pkt_cnt = round($row['l_others_pkt_cnt'],0);
	  
	  $w_tcp_pkt_cnt = round($row['w_tcp_pkt_cnt'],0);
	  $w_udp_pkt_cnt = round($row['w_udp_pkt_cnt'],0);
	  $w_icmp_pkt_cnt = round($row['w_icmp_pkt_cnt'],0);
	  $w_sctp_pkt_cnt = round($row['w_sctp_pkt_cnt'],0);
	  $w_others_pkt_cnt = round($row['w_others_pkt_cnt'],0);
 }
}

print '<script type="text/javascript">';
$tcp = "TCP $l_tcp_pkt_cnt";
$udp = "UDP $l_udp_pkt_cnt";
$icmp = "ICMP $l_icmp_pkt_cnt";
$sctp = "SCTP $l_sctp_pkt_cnt";
$others = "Others $l_others_pkt_cnt";
print '$(function () { 
    var lan_data_pkts = [
        {label: "'.$tcp.'", '.$color_green.', data:'.$l_tcp_pkt_cnt.'},
        {label: "'.$udp.'", '.$color_yellow.', data:'.$l_udp_pkt_cnt.'},
        {label: "'.$icmp.'", '.$color_red.', data:'.$l_icmp_pkt_cnt.'},
        {label: "'.$sctp.'", '.$color_blue.', data:'.$l_sctp_pkt_cnt.'},
        {label: "'.$others.'", '.$color_gray.', data:'.$l_others_pkt_cnt.'}
    ];';
    
$tcp = "TCP $w_tcp_pkt_cnt";
$udp = "UDP $w_udp_pkt_cnt";
$icmp = "ICMP $w_icmp_pkt_cnt";
$sctp = "SCTP $w_sctp_pkt_cnt";
$others = "Others $w_others_pkt_cnt";
print 'var wan_data_pkts = [
        {label: "'.$tcp.'", '.$color_green.', data:'.$w_tcp_pkt_cnt.'},
        {label: "'.$udp.'", '.$color_yellow.', data:'.$w_udp_pkt_cnt.'},
        {label: "'.$icmp.'", '.$color_red.', data:'.$w_icmp_pkt_cnt.'},
        {label: "'.$sctp.'", '.$color_blue.', data:'.$w_sctp_pkt_cnt.'},
        {label: "'.$others.'", '.$color_gray.', data:'.$w_others_pkt_cnt.'}
    ];';
    
print 'var options_pkts = { series: { pie: {show: true, innerRadius: 0.3,radius:44} },legend: {position:"se",borderColor:"#ffffff"}   };
    $.plot($("#flotcontainerlanpkts"), lan_data_pkts, options_pkts);
    $.plot($("#flotcontainerwanpkts"), wan_data_pkts, options_pkts);
      
});';
print '</script>';

?>
<tr><td><div id="flotcontainerlanpkts"></div></td><td><div id="flotcontainerwanpkts"></div></td></tr>
<?php
$total_l_pkt_cnt = $l_tcp_pkt_cnt + $l_udp_pkt_cnt + $l_icmp_pkt_cnt + $l_sctp_pkt_cnt + $l_others_pkt_cnt;
$total_w_pkt_cnt = $w_tcp_pkt_cnt + $w_udp_pkt_cnt + $w_icmp_pkt_cnt + $w_sctp_pkt_cnt + $w_others_pkt_cnt; 
print "<tr><td id=\"td\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Total Packets $total_l_pkt_cnt</td><td id=\"td\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Total Packets $total_w_pkt_cnt</td></tr>";
?>
</table><br>




<br><b>Packet Sizes Analysis: <i>(in Thousands)</i></b><br>
<table class="grid_style" width="550">
<tr><td id="table_top_heading">&nbsp;&nbsp;&nbsp;LAN Port - In</td><td id="table_top_heading">&nbsp;&nbsp;&nbsp;LAN Port - Out</td>
<td id="table_top_heading">&nbsp;&nbsp;&nbsp;WAN Port - In</td><td id="table_top_heading">&nbsp;&nbsp;&nbsp;WAN Port - Out</td></tr>
<?php
$query = "select 
sum(l_in_pkt_cnt_0_63)/1000 l_in_pkt_cnt_0_63, sum(l_in_pkt_cnt_64_127)/1000 l_in_pkt_cnt_64_127,
sum(l_in_pkt_cnt_128_255)/1000 l_in_pkt_cnt_128_255, sum(l_in_pkt_cnt_256_511)/1000 l_in_pkt_cnt_256_511,
sum(l_in_pkt_cnt_512_1023)/1000 l_in_pkt_cnt_512_1023, sum(l_in_pkt_cnt_1024_above)/1000 l_in_pkt_cnt_1024_above from stats_pkt_sizes";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
 while($row = mysql_fetch_array($result))
 {
	  $l_in_pkt_cnt_0_63 = round($row['l_in_pkt_cnt_0_63'], 0);
	  $l_in_pkt_cnt_64_127 = round($row['l_in_pkt_cnt_64_127'], 0);
	  $l_in_pkt_cnt_128_255 = round($row['l_in_pkt_cnt_128_255'], 0);
	  $l_in_pkt_cnt_256_511 = round($row['l_in_pkt_cnt_256_511'], 0);
	  $l_in_pkt_cnt_512_1023 = round($row['l_in_pkt_cnt_512_1023'], 0);
	  $l_in_pkt_cnt_1024_above = round($row['l_in_pkt_cnt_1024_above'], 0);
 }
}

$query = "select 
sum(l_out_pkt_cnt_0_63)/1000 l_out_pkt_cnt_0_63, sum(l_out_pkt_cnt_64_127)/1000 l_out_pkt_cnt_64_127,
sum(l_out_pkt_cnt_128_255)/1000 l_out_pkt_cnt_128_255, sum(l_out_pkt_cnt_256_511)/1000 l_out_pkt_cnt_256_511,
sum(l_out_pkt_cnt_512_1023)/1000 l_out_pkt_cnt_512_1023, sum(l_out_pkt_cnt_1024_above)/1000 l_out_pkt_cnt_1024_above from stats_pkt_sizes";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
 while($row = mysql_fetch_array($result))
 {
	  $l_out_pkt_cnt_0_63 = round($row['l_out_pkt_cnt_0_63'], 0);
	  $l_out_pkt_cnt_64_127 = round($row['l_out_pkt_cnt_64_127'], 0);
	  $l_out_pkt_cnt_128_255 = round($row['l_out_pkt_cnt_128_255'], 0);
	  $l_out_pkt_cnt_256_511 = round($row['l_out_pkt_cnt_256_511'], 0);
	  $l_out_pkt_cnt_512_1023 = round($row['l_out_pkt_cnt_512_1023'], 0);
	  $l_out_pkt_cnt_1024_above = round($row['l_out_pkt_cnt_1024_above'], 0);
 }
}

$query = "select 
sum(w_in_pkt_cnt_0_63)/1000 w_in_pkt_cnt_0_63, sum(w_in_pkt_cnt_64_127)/1000 w_in_pkt_cnt_64_127,
sum(w_in_pkt_cnt_128_255)/1000 w_in_pkt_cnt_128_255, sum(w_in_pkt_cnt_256_511)/1000 w_in_pkt_cnt_256_511,
sum(w_in_pkt_cnt_512_1023)/1000 w_in_pkt_cnt_512_1023, sum(w_in_pkt_cnt_1024_above)/1000 w_in_pkt_cnt_1024_above from stats_pkt_sizes";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
 while($row = mysql_fetch_array($result))
 {
	  $w_in_pkt_cnt_0_63 = round($row['w_in_pkt_cnt_0_63'], 0);
	  $w_in_pkt_cnt_64_127 = round($row['w_in_pkt_cnt_64_127'], 0);
	  $w_in_pkt_cnt_128_255 = round($row['w_in_pkt_cnt_128_255'], 0);
	  $w_in_pkt_cnt_256_511 = round($row['w_in_pkt_cnt_256_511'], 0);
	  $w_in_pkt_cnt_512_1023 = round($row['w_in_pkt_cnt_512_1023'], 0);
	  $w_in_pkt_cnt_1024_above = round($row['w_in_pkt_cnt_1024_above'], 0);
 }
}

$query = "select 
sum(w_out_pkt_cnt_0_63)/1000 w_out_pkt_cnt_0_63, sum(w_out_pkt_cnt_64_127)/1000 w_out_pkt_cnt_64_127,
sum(w_out_pkt_cnt_128_255)/1000 w_out_pkt_cnt_128_255, sum(w_out_pkt_cnt_256_511)/1000 w_out_pkt_cnt_256_511,
sum(w_out_pkt_cnt_512_1023)/1000 w_out_pkt_cnt_512_1023, sum(w_out_pkt_cnt_1024_above)/1000 w_out_pkt_cnt_1024_above from stats_pkt_sizes";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
 while($row = mysql_fetch_array($result))
 {
	  $w_out_pkt_cnt_0_63 = round($row['w_out_pkt_cnt_0_63'], 0);
	  $w_out_pkt_cnt_64_127 = round($row['w_out_pkt_cnt_64_127'], 0);
	  $w_out_pkt_cnt_128_255 = round($row['w_out_pkt_cnt_128_255'], 0);
	  $w_out_pkt_cnt_256_511 = round($row['w_out_pkt_cnt_256_511'], 0);
	  $w_out_pkt_cnt_512_1023 = round($row['w_out_pkt_cnt_512_1023'], 0);
	  $w_out_pkt_cnt_1024_above = round($row['w_out_pkt_cnt_1024_above'], 0);
 }
}


print '<script type="text/javascript">';
$label_l_in_pkt_cnt_0_63 = "0_63 $l_in_pkt_cnt_0_63";
$label_l_in_pkt_cnt_64_127 = "64_127 $l_in_pkt_cnt_64_127";
$label_l_in_pkt_cnt_128_255 = "128_255 $l_in_pkt_cnt_128_255";
$label_l_in_pkt_cnt_256_511 = "256_511 $l_in_pkt_cnt_256_511";
$label_l_in_pkt_cnt_512_1023 = "512_1023 $l_in_pkt_cnt_512_1023";
$label_l_in_pkt_cnt_1024_above = ">1024 $l_in_pkt_cnt_1024_above";

$label_l_out_pkt_cnt_0_63 = "0_63 $l_out_pkt_cnt_0_63";
$label_l_out_pkt_cnt_64_127 = "64_127 $l_out_pkt_cnt_64_127";
$label_l_out_pkt_cnt_128_255 = "128_255 $l_out_pkt_cnt_128_255";
$label_l_out_pkt_cnt_256_511 = "256_511 $l_out_pkt_cnt_256_511";
$label_l_out_pkt_cnt_512_1023 = "512_1023 $l_out_pkt_cnt_512_1023";
$label_l_out_pkt_cnt_1024_above = ">1024 $l_out_pkt_cnt_1024_above";

$label_w_in_pkt_cnt_0_63 = "0_63 $w_in_pkt_cnt_0_63";
$label_w_in_pkt_cnt_64_127 = "64_127 $w_in_pkt_cnt_64_127";
$label_w_in_pkt_cnt_128_255 = "128_255 $w_in_pkt_cnt_128_255";
$label_w_in_pkt_cnt_256_511 = "256_511 $w_in_pkt_cnt_256_511";
$label_w_in_pkt_cnt_512_1023 = "512_1023 $w_in_pkt_cnt_512_1023";
$label_w_in_pkt_cnt_1024_above = ">1024 $w_in_pkt_cnt_1024_above";

$label_w_out_pkt_cnt_0_63 = "0_63 $w_out_pkt_cnt_0_63";
$label_w_out_pkt_cnt_64_127 = "64_127 $w_out_pkt_cnt_64_127";
$label_w_out_pkt_cnt_128_255 = "128_255 $w_out_pkt_cnt_128_255";
$label_w_out_pkt_cnt_256_511 = "256_511 $w_out_pkt_cnt_256_511";
$label_w_out_pkt_cnt_512_1023 = "512_1023 $w_out_pkt_cnt_512_1023";
$label_w_out_pkt_cnt_1024_above = ">1024 $w_out_pkt_cnt_1024_above";

print '$(function () { 
   var l_in_pkt_cnt = [
      {label: "'.$label_l_in_pkt_cnt_0_63.'", '.$color_green.', data:'.$l_in_pkt_cnt_0_63.'},
      {label: "'.$label_l_in_pkt_cnt_64_127.'", '.$color_yellow.', data:'.$l_in_pkt_cnt_64_127.'},
      {label: "'.$label_l_in_pkt_cnt_128_255.'", '.$color_red.', data:'.$l_in_pkt_cnt_128_255.'},
      {label: "'.$label_l_in_pkt_cnt_256_511.'", '.$color_blue.', data:'.$l_in_pkt_cnt_256_511.'},
      {label: "'.$label_l_in_pkt_cnt_512_1023.'", '.$color_gray.', data:'.$l_in_pkt_cnt_512_1023.'},
      {label: "'.$label_l_in_pkt_cnt_1024_above.'", '.$color_black.', data:'.$l_in_pkt_cnt_1024_above.'}
   ];';

print 'var l_out_pkt_cnt = [
      {label: "'.$label_l_out_pkt_cnt_0_63.'", '.$color_green.', data:'.$l_out_pkt_cnt_0_63.'},
      {label: "'.$label_l_out_pkt_cnt_64_127.'", '.$color_yellow.', data:'.$l_out_pkt_cnt_64_127.'},
      {label: "'.$label_l_out_pkt_cnt_128_255.'", '.$color_red.', data:'.$l_out_pkt_cnt_128_255.'},
      {label: "'.$label_l_out_pkt_cnt_256_511.'", '.$color_blue.', data:'.$l_out_pkt_cnt_256_511.'},
      {label: "'.$label_l_out_pkt_cnt_512_1023.'", '.$color_gray.', data:'.$l_out_pkt_cnt_512_1023.'},
      {label: "'.$label_l_out_pkt_cnt_1024_above.'", '.$color_black.', data:'.$l_out_pkt_cnt_1024_above.'}
   ];';

print 'var w_in_pkt_cnt = [
      {label: "'.$label_w_in_pkt_cnt_0_63.'", '.$color_green.', data:'.$w_in_pkt_cnt_0_63.'},
      {label: "'.$label_w_in_pkt_cnt_64_127.'", '.$color_yellow.', data:'.$w_in_pkt_cnt_64_127.'},
      {label: "'.$label_w_in_pkt_cnt_128_255.'", '.$color_red.', data:'.$w_in_pkt_cnt_128_255.'},
      {label: "'.$label_w_in_pkt_cnt_256_511.'", '.$color_blue.', data:'.$w_in_pkt_cnt_256_511.'},
      {label: "'.$label_w_in_pkt_cnt_512_1023.'", '.$color_gray.', data:'.$w_in_pkt_cnt_512_1023.'},
      {label: "'.$label_w_in_pkt_cnt_1024_above.'", '.$color_black.', data:'.$w_in_pkt_cnt_1024_above.'}
   ];';

print 'var w_out_pkt_cnt = [
      {label: "'.$label_w_out_pkt_cnt_0_63.'", '.$color_green.', data:'.$w_out_pkt_cnt_0_63.'},
      {label: "'.$label_w_out_pkt_cnt_64_127.'", '.$color_yellow.', data:'.$w_out_pkt_cnt_64_127.'},
      {label: "'.$label_w_out_pkt_cnt_128_255.'", '.$color_red.', data:'.$w_out_pkt_cnt_128_255.'},
      {label: "'.$label_w_out_pkt_cnt_256_511.'", '.$color_blue.', data:'.$w_out_pkt_cnt_256_511.'},
      {label: "'.$label_w_out_pkt_cnt_512_1023.'", '.$color_gray.', data:'.$w_out_pkt_cnt_512_1023.'},
      {label: "'.$label_w_out_pkt_cnt_1024_above.'", '.$color_black.', data:'.$w_out_pkt_cnt_1024_above.'}
   ];';

print 'var options_pkt_sizes = { series: { pie: {show: true, innerRadius: 0.3,radius:44} },legend: {position:"se",borderColor:"#ffffff"}   };
    $.plot($("#l_in_pktsizes"), l_in_pkt_cnt, options_pkt_sizes);
    $.plot($("#l_out_pktsizes"), l_out_pkt_cnt, options_pkt_sizes);
    $.plot($("#w_in_pktsizes"), w_in_pkt_cnt, options_pkt_sizes);
    $.plot($("#w_out_pktsizes"), w_out_pkt_cnt, options_pkt_sizes);
});';
print '</script>';

?>
<tr><td><br><div id="l_in_pktsizes"></div></td><td><br><div id="l_out_pktsizes"></div></td>
<td><br><div id="w_in_pktsizes"></div></td><td><br><div id="w_out_pktsizes"></div></td>
</tr>
<?php
//$total_l_pkt_cnt = $l_tcp_pkt_cnt + $l_udp_pkt_cnt + $l_icmp_pkt_cnt + $l_sctp_pkt_cnt + $l_others_pkt_cnt;
//$total_w_pkt_cnt = $w_tcp_pkt_cnt + $w_udp_pkt_cnt + $w_icmp_pkt_cnt + $w_sctp_pkt_cnt + $w_others_pkt_cnt; 
//print "<tr><td id=\"td\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Total Packets $total_l_pkt_cnt</td><td id=\"td\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Total Packets $total_w_pkt_cnt</td></tr>";
?>
</table><br><br>

