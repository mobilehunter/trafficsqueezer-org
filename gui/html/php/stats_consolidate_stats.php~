<?php include("/var/www/html/c/c_db_access.php");

//Consolidate for every 720 minutes, that is 2 times a day (60mins*12hours) once consolidate old entries !
$query_condition=" where timestamp<=DATE_SUB(NOW(),INTERVAL 720 MINUTE) and type=0 limit 500";
$output="";

$query = "select avg(lan_stats_pct) lan_stats_pct, avg(wan_stats_pct) wan_stats_pct,
          sum(lan_rx) lan_rx, sum(lan_tx) lan_tx, sum(lan_bytes_saved) lan_bytes_saved, 
          sum(wan_rx) wan_rx, sum(wan_tx) wan_tx, sum(wan_bytes_saved) wan_bytes_saved 
          from stats_overall $query_condition";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
	while($row = mysql_fetch_array($result))
 {
	  $lan_stats_pct = $row['lan_stats_pct'];
	  $wan_stats_pct = $row['wan_stats_pct'];
	  $lan_rx = $row['lan_rx'];
	  $lan_tx = $row['lan_tx'];
	  $lan_bytes_saved = $row['lan_bytes_saved'];
	  $wan_rx = $row['wan_rx'];
	  $wan_tx = $row['wan_tx'];
	  $wan_bytes_saved = $row['wan_bytes_saved'];
	  $query = "insert into stats_overall (type, timestamp, lan_stats_pct, wan_stats_pct, lan_rx, lan_tx, wan_rx, wan_tx, lan_bytes_saved, wan_bytes_saved) ";
	  $query .= "values (1, now(), $lan_stats_pct, $wan_stats_pct, $lan_rx, $lan_tx, $wan_rx, $wan_tx, $lan_bytes_saved, $wan_bytes_saved)";
	  print "$query <br>\n";
     mysql_query($query, $db);
     $query = "delete from stats_overall $query_condition";
     print "$query <br><hr>\n\n";
     mysql_query($query, $db);
 }
}


$query = "select sum(l_tcp_pkt_cnt) l_tcp_pkt_cnt, sum(l_udp_pkt_cnt) l_udp_pkt_cnt, sum(l_icmp_pkt_cnt) l_icmp_pkt_cnt, sum(l_sctp_pkt_cnt) l_sctp_pkt_cnt, sum(l_others_pkt_cnt) l_others_pkt_cnt, 
			 sum(w_tcp_pkt_cnt) w_tcp_pkt_cnt, sum(w_udp_pkt_cnt) w_udp_pkt_cnt, sum(w_icmp_pkt_cnt) w_icmp_pkt_cnt, sum(w_sctp_pkt_cnt) w_sctp_pkt_cnt, sum(w_others_pkt_cnt) w_others_pkt_cnt
			 from stats_ip_proto $query_condition";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
 while($row = mysql_fetch_array($result))
 {
	  $l_tcp_pkt_cnt = $row['l_tcp_pkt_cnt'];
	  $l_udp_pkt_cnt = $row['l_udp_pkt_cnt'];
	  $l_icmp_pkt_cnt = $row['l_icmp_pkt_cnt'];
	  $l_sctp_pkt_cnt = $row['l_sctp_pkt_cnt'];
	  $l_others_pkt_cnt = $row['l_others_pkt_cnt'];
	  $w_tcp_pkt_cnt = $row['w_tcp_pkt_cnt'];
	  $w_udp_pkt_cnt = $row['w_udp_pkt_cnt'];
	  $w_icmp_pkt_cnt = $row['w_icmp_pkt_cnt'];
	  $w_sctp_pkt_cnt = $row['w_sctp_pkt_cnt'];
	  $w_others_pkt_cnt = $row['w_others_pkt_cnt'];
	  $query  = "insert into stats_ip_proto (type, timestamp, l_tcp_pkt_cnt, l_udp_pkt_cnt, l_icmp_pkt_cnt, l_sctp_pkt_cnt, l_others_pkt_cnt, l_units_format, w_tcp_pkt_cnt, w_udp_pkt_cnt, w_icmp_pkt_cnt, w_sctp_pkt_cnt, w_others_pkt_cnt, w_units_format)";
	  $query .= "values (1, now(), $l_tcp_pkt_cnt, $l_udp_pkt_cnt, $l_icmp_pkt_cnt, $l_sctp_pkt_cnt, $l_others_pkt_cnt, '-', $w_tcp_pkt_cnt, $w_udp_pkt_cnt, $w_icmp_pkt_cnt, $w_sctp_pkt_cnt, $w_others_pkt_cnt, '-')";
     mysql_query($query, $db);
     print "$query<br>\n";
     $query = "delete from stats_ip_proto $query_condition";
     print "$query <br><hr>\n\n";
     mysql_query($query, $db);
 }
}


$query = "select 
sum(l_in_pkt_cnt_0_63) l_in_pkt_cnt_0_63, sum(l_in_pkt_cnt_64_127) l_in_pkt_cnt_64_127,
sum(l_in_pkt_cnt_128_255) l_in_pkt_cnt_128_255, sum(l_in_pkt_cnt_256_511) l_in_pkt_cnt_256_511,
sum(l_in_pkt_cnt_512_1023) l_in_pkt_cnt_512_1023, sum(l_in_pkt_cnt_1024_above) l_in_pkt_cnt_1024_above,
sum(l_out_pkt_cnt_0_63) l_out_pkt_cnt_0_63, sum(l_out_pkt_cnt_64_127) l_out_pkt_cnt_64_127,
sum(l_out_pkt_cnt_128_255) l_out_pkt_cnt_128_255, sum(l_out_pkt_cnt_256_511) l_out_pkt_cnt_256_511,
sum(l_out_pkt_cnt_512_1023) l_out_pkt_cnt_512_1023, sum(l_out_pkt_cnt_1024_above) l_out_pkt_cnt_1024_above,
sum(w_in_pkt_cnt_0_63) w_in_pkt_cnt_0_63, sum(w_in_pkt_cnt_64_127) w_in_pkt_cnt_64_127,
sum(w_in_pkt_cnt_128_255) w_in_pkt_cnt_128_255, sum(w_in_pkt_cnt_256_511) w_in_pkt_cnt_256_511,
sum(w_in_pkt_cnt_512_1023) w_in_pkt_cnt_512_1023, sum(w_in_pkt_cnt_1024_above) w_in_pkt_cnt_1024_above,
sum(w_out_pkt_cnt_0_63) w_out_pkt_cnt_0_63, sum(w_out_pkt_cnt_64_127) w_out_pkt_cnt_64_127,
sum(w_out_pkt_cnt_128_255) w_out_pkt_cnt_128_255, sum(w_out_pkt_cnt_256_511) w_out_pkt_cnt_256_511,
sum(w_out_pkt_cnt_512_1023) w_out_pkt_cnt_512_1023, sum(w_out_pkt_cnt_1024_above) w_out_pkt_cnt_1024_above
from stats_pkt_sizes $query_condition";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
 while($row = mysql_fetch_array($result))
 {
	  $l_in_pkt_cnt_0_63 = $row['l_in_pkt_cnt_0_63'];
	  $l_in_pkt_cnt_64_127 = $row['l_in_pkt_cnt_64_127'];
	  $l_in_pkt_cnt_128_255 = $row['l_in_pkt_cnt_128_255'];
	  $l_in_pkt_cnt_256_511 = $row['l_in_pkt_cnt_256_511'];
	  $l_in_pkt_cnt_512_1023 = $row['l_in_pkt_cnt_512_1023'];
	  $l_in_pkt_cnt_1024_above = $row['l_in_pkt_cnt_1024_above'];
	  $l_out_pkt_cnt_0_63 = $row['l_out_pkt_cnt_0_63'];
	  $l_out_pkt_cnt_64_127 = $row['l_out_pkt_cnt_64_127'];
	  $l_out_pkt_cnt_128_255 = $row['l_out_pkt_cnt_128_255'];
	  $l_out_pkt_cnt_256_511 = $row['l_out_pkt_cnt_256_511'];
	  $l_out_pkt_cnt_512_1023 = $row['l_out_pkt_cnt_512_1023'];
	  $l_out_pkt_cnt_1024_above = $row['l_out_pkt_cnt_1024_above'];
	  $w_in_pkt_cnt_0_63 = $row['w_in_pkt_cnt_0_63'];
	  $w_in_pkt_cnt_64_127 = $row['w_in_pkt_cnt_64_127'];
	  $w_in_pkt_cnt_128_255 = $row['w_in_pkt_cnt_128_255'];
	  $w_in_pkt_cnt_256_511 = $row['w_in_pkt_cnt_256_511'];
	  $w_in_pkt_cnt_512_1023 = $row['w_in_pkt_cnt_512_1023'];
	  $w_in_pkt_cnt_1024_above = $row['w_in_pkt_cnt_1024_above'];
	  $w_out_pkt_cnt_0_63 = $row['w_out_pkt_cnt_0_63'];
	  $w_out_pkt_cnt_64_127 = $row['w_out_pkt_cnt_64_127'];
	  $w_out_pkt_cnt_128_255 = $row['w_out_pkt_cnt_128_255'];
	  $w_out_pkt_cnt_256_511 = $row['w_out_pkt_cnt_256_511'];
	  $w_out_pkt_cnt_512_1023 = $row['w_out_pkt_cnt_512_1023'];
	  $w_out_pkt_cnt_1024_above = $row['w_out_pkt_cnt_1024_above'];

	  $query  = "insert into stats_pkt_sizes (type, timestamp, ";
	  $query .= "l_in_pkt_cnt_0_63, l_in_pkt_cnt_64_127, l_in_pkt_cnt_128_255, l_in_pkt_cnt_256_511, l_in_pkt_cnt_512_1023, l_in_pkt_cnt_1024_above,";
	  $query .= "l_out_pkt_cnt_0_63, l_out_pkt_cnt_64_127, l_out_pkt_cnt_128_255, l_out_pkt_cnt_256_511, l_out_pkt_cnt_512_1023, l_out_pkt_cnt_1024_above,";
	  $query .= "w_in_pkt_cnt_0_63, w_in_pkt_cnt_64_127, w_in_pkt_cnt_128_255, w_in_pkt_cnt_256_511, w_in_pkt_cnt_512_1023, w_in_pkt_cnt_1024_above,";
	  $query .= "w_out_pkt_cnt_0_63, w_out_pkt_cnt_64_127, w_out_pkt_cnt_128_255, w_out_pkt_cnt_256_511, w_out_pkt_cnt_512_1023, w_out_pkt_cnt_1024_above";
	  $query .= ")";
	  $query .= "values (1, now(), ";
	  $query .= "$l_in_pkt_cnt_0_63, $l_in_pkt_cnt_64_127, $l_in_pkt_cnt_128_255, $l_in_pkt_cnt_256_511, $l_in_pkt_cnt_512_1023, $l_in_pkt_cnt_1024_above,";
	  $query .= "$l_out_pkt_cnt_0_63, $l_out_pkt_cnt_64_127, $l_out_pkt_cnt_128_255, $l_out_pkt_cnt_256_511, $l_out_pkt_cnt_512_1023, $l_out_pkt_cnt_1024_above,";
	  $query .= "$w_in_pkt_cnt_0_63, $w_in_pkt_cnt_64_127, $w_in_pkt_cnt_128_255, $w_in_pkt_cnt_256_511, $w_in_pkt_cnt_512_1023, $w_in_pkt_cnt_1024_above,";
	  $query .= "$w_out_pkt_cnt_0_63, $w_out_pkt_cnt_64_127, $w_out_pkt_cnt_128_255, $w_out_pkt_cnt_256_511, $w_out_pkt_cnt_512_1023, $w_out_pkt_cnt_1024_above";
	  $query .= ")";
     mysql_query($query, $db);
     print "$query\n";
     $query = "delete from stats_pkt_sizes $query_condition";
     print "$query \n\n";
     mysql_query($query, $db);
 }
}


?>
