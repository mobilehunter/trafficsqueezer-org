<?php include("/var/www/html/c/c_db_access.php");

function calculate_stats_pct($lan_rx, $lan_tx, $wan_rx, $wan_tx, & $lan_stats_pct, & $wan_stats_pct)
{
	$lan_stats_pct=round((($lan_rx-$lan_tx)*100)/$lan_rx, 0);
	$wan_stats_pct=round((($wan_tx-$wan_rx)*100)/$wan_tx, 0);
}

	
$file = fopen("/proc/trafficsqueezer/stats", "r") or exit("Unable to open file!");
while(!feof($file))
{
	 $buffer = fgets($file, 4096);
	 if(!strncmp($buffer, "overall|", strlen("overall|")))
	 {
			$array = explode('|', $buffer);
			$lan_rx = $array[1];
			$lan_tx = $array[2];
			$wan_rx = $array[3];
			$wan_tx = $array[4];
			$lan_stats_pct = 0;
			$wan_stats_pct = 0;
			calculate_stats_pct($lan_rx, $lan_tx, $wan_rx, $wan_tx, $lan_stats_pct, $wan_stats_pct );
			$lan_bytes_saved = $lan_rx-$lan_tx;
			$wan_bytes_saved = $wan_tx-$wan_rx;
			$lan_rx = round($lan_rx/1024, 0);
			$lan_tx = round($lan_tx/1024, 0);
			$wan_rx = round($wan_rx/1024, 0);
			$wan_tx = round($wan_tx/1024, 0);
			$lan_bytes_saved = round($lan_rx-$lan_tx, 0);
			$wan_bytes_saved = round($wan_tx-$wan_rx, 0);
			
			if($lan_stats_pct==0 && $wan_stats_pct==0 && $lan_rx==0 && $lan_tx==0 && $wan_rx==0 && $wan_tx==0 && $lan_bytes_saved==0 && $wan_bytes_saved==0) 
			{	print "overall| Complete zero entry, ignoring this data entry !\n"; }
			else
			{	$query = "insert into stats_overall (timestamp, lan_stats_pct, wan_stats_pct, lan_rx, lan_tx, wan_rx, wan_tx, lan_bytes_saved, wan_bytes_saved) ";
				$query .= "values (now(), $lan_stats_pct, $wan_stats_pct, $lan_rx, $lan_tx, $wan_rx, $wan_tx, $lan_bytes_saved, $wan_bytes_saved)";
				print "$query <br><hr>\n";
      		mysql_query($query, $db);
      	}
	 }else if(!strncmp($buffer, "ip_proto|", strlen("ip_proto|")))
	 {
			$array = explode('|', $buffer);
			$l_tcp_pkt_cnt    = $array[1];
			$l_udp_pkt_cnt    = $array[2];
			$l_icmp_pkt_cnt   = $array[3];
			$l_sctp_pkt_cnt   = $array[4];
			$l_others_pkt_cnt = $array[5];
			$l_units_format	= '-';
			$w_tcp_pkt_cnt		= $array[6];
			$w_udp_pkt_cnt		= $array[7];
			$w_icmp_pkt_cnt	= $array[8];
			$w_sctp_pkt_cnt	= $array[9];
			$w_others_pkt_cnt	= $array[10];
			$w_units_format	= '-';
			
			if($l_tcp_pkt_cnt==0 && $l_udp_pkt_cnt==0 && $l_icmp_pkt_cnt==0 && $l_sctp_pkt_cnt==0 && $l_others_pkt_cnt==0 && $w_tcp_pkt_cnt==0 && $w_udp_pkt_cnt==0 && $w_icmp_pkt_cnt==0 && $w_sctp_pkt_cnt==0 && $w_others_pkt_cnt==0)
			{	print "ip_proto| Complete zero entry, ignoring this data entry !\n"; }
			else
			{ 
				$query  = "insert into stats_ip_proto ( timestamp, l_tcp_pkt_cnt, l_udp_pkt_cnt, l_icmp_pkt_cnt, l_sctp_pkt_cnt, l_others_pkt_cnt, l_units_format, w_tcp_pkt_cnt, w_udp_pkt_cnt, w_icmp_pkt_cnt, w_sctp_pkt_cnt, w_others_pkt_cnt, w_units_format)";
				$query .= "values (now(), $l_tcp_pkt_cnt, $l_udp_pkt_cnt, $l_icmp_pkt_cnt, $l_sctp_pkt_cnt, $l_others_pkt_cnt, '$l_units_format', $w_tcp_pkt_cnt, $w_udp_pkt_cnt, $w_icmp_pkt_cnt, $w_sctp_pkt_cnt, $w_others_pkt_cnt, '$w_units_format')";
      		mysql_query($query, $db);
      		print "$query<br><hr>\n";
      	}
	 }else if(!strncmp($buffer, "pkt_sizes|", strlen("pkt_sizes|")))
	 {
			 $array = explode('|', $buffer);
			 $l_in_pkt_cnt_0_63   		= $array[1];   
			 $l_out_pkt_cnt_0_63  		= $array[2];     
			 $w_in_pkt_cnt_64_127 		= $array[3];     
			 $w_out_pkt_cnt_64_127		= $array[4];     
			 $l_in_pkt_cnt_128_255		= $array[5];     
			 $l_out_pkt_cnt_128_255		= $array[6];    
			 $l_in_pkt_cnt_256_511     = $array[7];
			 $l_out_pkt_cnt_256_511    = $array[8];
			 $l_in_pkt_cnt_512_1023    = $array[9];
			 $l_out_pkt_cnt_512_1023   = $array[10];
			 $l_in_pkt_cnt_1024_above  = $array[11];
			 $l_out_pkt_cnt_1024_above = $array[12];
			 $w_in_pkt_cnt_0_63   		= $array[13];     
			 $w_out_pkt_cnt_0_63  		= $array[14];     
			 $l_in_pkt_cnt_64_127 		= $array[15];     
			 $l_out_pkt_cnt_64_127		= $array[16];     
			 $w_in_pkt_cnt_128_255     = $array[17];    
			 $w_out_pkt_cnt_128_255    = $array[18];
			 $w_in_pkt_cnt_256_511     = $array[19];
			 $w_out_pkt_cnt_256_511    = $array[20];
			 $w_in_pkt_cnt_512_1023    = $array[21];
			 $w_out_pkt_cnt_512_1023   = $array[22];
			 $w_in_pkt_cnt_1024_above  = $array[23];
			 $w_out_pkt_cnt_1024_above = $array[24];
			 $l_units_format           = '-';
			 $e_units_format           = '-';

			if($l_in_pkt_cnt_0_63==0 && $l_out_pkt_cnt_0_63==0 && $w_in_pkt_cnt_0_63==0 && $w_out_pkt_cnt_0_63==0 && $l_in_pkt_cnt_64_127==0 && $l_out_pkt_cnt_64_127==0 && $w_in_pkt_cnt_64_127==0 && $w_out_pkt_cnt_64_127==0 && $l_in_pkt_cnt_128_255==0 && $l_out_pkt_cnt_128_255==0 && $w_in_pkt_cnt_128_255==0 && $w_out_pkt_cnt_128_255==0 && $l_in_pkt_cnt_256_511==0 && $l_out_pkt_cnt_256_511==0 && $w_in_pkt_cnt_256_511==0 && $w_out_pkt_cnt_256_511==0 && $l_in_pkt_cnt_512_1023==0 && $l_out_pkt_cnt_512_1023==0 && $w_in_pkt_cnt_512_1023==0 && $w_out_pkt_cnt_512_1023==0 && $l_in_pkt_cnt_1024_above==0 && $l_out_pkt_cnt_1024_above==0 && $w_in_pkt_cnt_1024_above==0 && $w_out_pkt_cnt_1024_above==0)
			{	print "pkt_sizes| Complete zero entry, ignoring this data entry !\n"; }
			else
			{ 
				$query  = "insert into stats_pkt_sizes ( timestamp,  l_in_pkt_cnt_0_63, l_out_pkt_cnt_0_63, w_in_pkt_cnt_0_63, w_out_pkt_cnt_0_63, l_in_pkt_cnt_64_127, l_out_pkt_cnt_64_127, w_in_pkt_cnt_64_127, w_out_pkt_cnt_64_127, l_in_pkt_cnt_128_255, l_out_pkt_cnt_128_255, w_in_pkt_cnt_128_255, w_out_pkt_cnt_128_255, l_in_pkt_cnt_256_511, l_out_pkt_cnt_256_511, w_in_pkt_cnt_256_511, w_out_pkt_cnt_256_511, l_in_pkt_cnt_512_1023, l_out_pkt_cnt_512_1023, w_in_pkt_cnt_512_1023, w_out_pkt_cnt_512_1023, l_in_pkt_cnt_1024_above, l_out_pkt_cnt_1024_above, w_in_pkt_cnt_1024_above, w_out_pkt_cnt_1024_above, l_units_format, e_units_format)";
				$query .= "values (now(),  $l_in_pkt_cnt_0_63, $l_out_pkt_cnt_0_63, $w_in_pkt_cnt_0_63, $w_out_pkt_cnt_0_63, $l_in_pkt_cnt_64_127, $l_out_pkt_cnt_64_127, $w_in_pkt_cnt_64_127, $w_out_pkt_cnt_64_127, $l_in_pkt_cnt_128_255, $l_out_pkt_cnt_128_255, $w_in_pkt_cnt_128_255, $w_out_pkt_cnt_128_255, $l_in_pkt_cnt_256_511, $l_out_pkt_cnt_256_511, $w_in_pkt_cnt_256_511, $w_out_pkt_cnt_256_511, $l_in_pkt_cnt_512_1023, $l_out_pkt_cnt_512_1023, $w_in_pkt_cnt_512_1023, $w_out_pkt_cnt_512_1023, $l_in_pkt_cnt_1024_above, $l_out_pkt_cnt_1024_above, $w_in_pkt_cnt_1024_above, $w_out_pkt_cnt_1024_above, '$l_units_format', '$e_units_format')";
      		$result = mysql_query($query, $db);
      		print "$query<br><hr>\n";
      	}
	 }else if(!strncmp($buffer, "coal|", strlen("coal|")))
	 {
			$array = explode('|', $buffer);
			$lan_rx  = $array[1];
			$lan_tx  = $array[2];
			$wan_rx   = $array[3];
			$wan_tx   = $array[4];
			calculate_stats_pct($lan_rx, $lan_tx, $wan_rx, $wan_tx, $lan_stats_pct, $wan_stats_pct );
			if($lan_stats_pct==0 && $wan_stats_pct==0 && $lan_rx==0 && $lan_tx==0 && $wan_rx==0 && $wan_tx==0) 
			{	print "coal| Complete zero entry, ignoring this data entry !\n"; }
			else
			{						
				$query = "insert into stats_coalescing ( timestamp, lan_stats_pct, wan_stats_pct) values (now(), $lan_stats_pct, $wan_stats_pct)";
				print "$query <br><hr>\n";
      		$result = mysql_query($query, $db);
      	}
	 }else if(!strncmp($buffer, "filter_dns|", strlen("filter_dns|")))
	 {
			$array = explode('|', $buffer);
			$lan_filter_dns_pkts = $array[1];
			$wan_filter_dns_pkts = $array[2];
			$lan_filter_dns_bytes_saved = $array[3];
			$wan_filter_dns_bytes_saved = $array[4];
			if($lan_filter_dns_pkts==0 && $wan_filter_dns_pkts==0 && $lan_filter_dns_bytes_saved==0 && $wan_filter_dns_bytes_saved==0) 
			{	print "filter_dns| Complete zero entry, ignoring this data entry !\n"; }
			else
			{
				$query = "insert into stats_filter_dns ( timestamp, lan_filter_dns_pkts, wan_filter_dns_pkts, lan_filter_dns_bytes_saved, wan_filter_dns_bytes_saved) values (now(), $lan_filter_dns_pkts, $wan_filter_dns_pkts, $lan_filter_dns_bytes_saved, $wan_filter_dns_bytes_saved)";
      		$result = mysql_query($query, $db);
      		print "$query";
      	}
	 }

}
fclose($file);


?>
