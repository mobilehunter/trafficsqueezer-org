<?php
error_reporting(5);
$dbHost = "localhost";
$dbUser = "root";
$dbPass = "welcome";
$dbDatabase = "aquarium";
$db = mysql_connect("$dbHost", "$dbUser", "$dbPass") or die ("Error connecting to database.");
mysql_select_db("$dbDatabase", $db) or die ("Couldn't select the database.");
generate_visible_hostname($db);
generate_http_port($db);
generate_cache_dir($db);
generate_acl($db);
generate_timeout($db);
generate_wccp($db);
generate_cache_tuning($db);
generate_http_accel($db);
function generate_cache_tuning($db)
{
	print "\n# Cache Tuning:\n";
	$query = "select wais_relay_host, wais_relay_port, request_header_max_size, request_body_max_size, reply_body_max_size, refresh_pattern, reference_age, quick_abort_min, quick_abort_max, quick_abort_pct, negative_ttl, positive_dns_ttl, negative_dns_ttl, range_offset_limit from squid_cache_tuning_cfg where id=1 ";
   $result = mysql_query($query, $db);
   $rowCheck = mysql_num_rows($result);
   if ($rowCheck > 0)
   {
      while ($row = mysql_fetch_array($result))
      {
   		if($row[wais_relay_host]!=NULL) print "wais_relay_host $row[wais_relay_host]\n";
 			if($row[wais_relay_port]!=NULL) print "wais_relay_port $row[wais_relay_port]\n";
 			if($row[request_header_max_size]!=NULL) print "request_header_max_size $row[request_header_max_size]\n";
 			if($row[request_body_max_size]!=NULL) print "request_body_max_size $row[request_body_max_size]\n";
 			if($row[reply_body_max_size]!=NULL) print "reply_body_max_size $row[reply_body_max_size]\n";
 			if($row[refresh_pattern]!=NULL) print "refresh_pattern $row[refresh_pattern]\n";
 			if($row[reference_age]!=NULL) print "reference_age $row[reference_age]\n";
 			if($row[quick_abort_min]!=NULL) print "quick_abort_min $row[quick_abort_min]\n";
 			if($row[quick_abort_max]!=NULL) print "quick_abort_max $row[quick_abort_max]\n";
			if($row[quick_abort_pct]!=NULL) print "quick_abort_pct $row[quick_abort_pct]\n";
			if($row[negative_ttl]!=NULL) print "negative_ttl $row[negative_ttl]\n";
			if($row[positive_dns_ttl]!=NULL) print "positive_dns_ttl $row[positive_dns_ttl]\n";
			if($row[negative_dns_ttl]!=NULL) print "negative_dns_ttl $row[negative_dns_ttl]\n";
			if($row[range_offset_limit]!=NULL) print "range_offset_limit $row[range_offset_limit]\n";
    	}							
	}
	print "#------------------------------------------------------\n";	
}

function generate_timeout($db)
{
	print "\n# Timeouts:\n";
	$query = "select connect_timeout, peer_connect_timeout, read_timeout, request_timeout, persistent_request_timeout, client_lifetime, half_closed_clients, pconn_timeout, ident_timeout, shutdown_lifetime from squid_timeout_cfg where id=1 ";
   $result = mysql_query($query, $db);
   $rowCheck = mysql_num_rows($result);
   if ($rowCheck > 0)
   {
      while ($row = mysql_fetch_array($result))
      {		
   		if($row[connect_timeout]!=NULL) print "connect_timeout $row[connect_timeout]\n";
 			if($row[peer_connect_timeout]!=NULL) print "peer_connect_timeout $row[peer_connect_timeout]\n";
 			if($row[read_timeout]!=NULL) print "read_timeout $row[read_timeout]\n";
 			if($row[request_timeout]!=NULL) print "request_timeout $row[request_timeout]\n";
 			if($row[persistent_request_timeout]!=NULL) print "persistent_request_timeout $row[persistent_request_timeout]\n";
 			if($row[half_closed_clients]!=NULL) print "half_closed_clients $row[half_closed_clients]\n";
 			if($row[pconn_timeout]!=NULL) print "pconn_timeout $row[pconn_timeout]\n";
 			if($row[ident_timeout]!=NULL) print "ident_timeout $row[ident_timeout]\n";
 			if($row[shutdown_lifetime]!=NULL) print "shutdown_lifetime $row[shutdown_lifetime]\n";
    	}							
	}
	print "#------------------------------------------------------\n";	
}


function generate_wccp($db)
{
	print "\n# WCCP Settings:\n";
	$query = "select wccp_router, wccp_version, wccp_incoming_address, wccp_outgoing_address, wccp2_router, wccp2_address, wccp2_forwarding_method, wccp2_assignment_method, wccp2_return_method, wccp2_service_standard  from squid_wccp_cfg where id=1 ";
   $result = mysql_query($query, $db);
   $rowCheck = mysql_num_rows($result);
   if ($rowCheck > 0)
   {
      while ($row = mysql_fetch_array($result))
      {		
   		if($row[wccp_router]!=NULL) print "wccp_router $row[wccp_router]\n";
   		if($row[wccp_version]!=NULL) print "wccp_version $row[wccp_version]\n";
   		if($row[wccp_incoming_address]!=NULL) print "wccp_incoming_address $row[wccp_incoming_address]\n";
   		if($row[wccp_outgoing_address]!=NULL) print "wccp_outgoing_address $row[wccp_outgoing_address]\n";
   		print "\n";
   		if($row[wccp2_address]!=NULL) print "wccp2_address $row[wccp2_address]\n";
   		if($row[wccp2_forwarding_method]!=NULL) print "wccp2_forwarding_method $row[wccp2_forwarding_method]\n";
   		if($row[wccp2_assignment_method]!=NULL) print "wccp2_assignment_method $row[wccp2_assignment_method]\n";
			if($row[wccp2_return_method]!=NULL) print "wccp2_return_method $row[wccp2_return_method]\n";
			if($row[wccp2_service_standard]!=NULL) print "wccp2_service_standard $row[wccp2_service_standard]\n";
    	}							
	}
	print "#------------------------------------------------------\n";	
}

function generate_http_port($db)
{
	print "\n";
	$query = "select http_port, ts_squid_device_mode from squid_cfg where id=1 ";
   $result = mysql_query($query, $db);
   $rowCheck = mysql_num_rows($result);
   if ($rowCheck > 0)
   {
      while ($row = mysql_fetch_array($result))
      {		
   		if($row[http_port]!=NULL)
   		{
   			print "http_port $row[http_port]";
   			if($row[ts_squid_device_mode]=="transparent") print " $row[ts_squid_device_mode]\n"; else print "\n";
   		}  
      }							
   }
   print "#------------------------------------------------------\n";	
}

function generate_visible_hostname($db)
{
	print "\n";
	$query = "select visible_hostname from squid_cfg where id=1 ";
   $result = mysql_query($query, $db);
   $rowCheck = mysql_num_rows($result);
   if ($rowCheck > 0)
   {
      while ($row = mysql_fetch_array($result))
      {		
   		if($row[visible_hostname]!=NULL)
   		{
   			print "visible_hostname $row[visible_hostname]\n";
   		}  
    	}							
	}
	print "#------------------------------------------------------\n";	
}

function generate_cache_dir($db)
{	print "\n# Basic Cache Directory settings:\n";
	$query = "select cache_dir from squid_cfg where id=1 ";
   $result = mysql_query($query, $db);
   $rowCheck = mysql_num_rows($result);
   if ($rowCheck > 0)
   {
      while ($row = mysql_fetch_array($result))
      {		
   		if($row[cache_dir]!=NULL)
   		{
   			print "cache_dir $row[cache_dir]\n";
   		}  
    	}							
	}
	print "#------------------------------------------------------\n";	
} /* generate_cache_dir */

function generate_acl($db)
{
	print "\n# ACLs:\n";
	$query = "select name, type from squid_acl_names_list ";
   $result = mysql_query($query, $db);
   $rowCheck = mysql_num_rows($result);
   if ($rowCheck > 0)
   {
      while ($row = mysql_fetch_array($result))
      {		
   		if($row[type]!=NULL)
   		{
   			
   			
				//Get ACL acls/rules list
				$query2 = "select value from squid_acl_list where name=\"$row[name]\" ";
   			$result2 = mysql_query($query2, $db);
   			$rowCheck2 = mysql_num_rows($result2);
   			if ($rowCheck2 > 0)
   			{
      			while ($row2 = mysql_fetch_array($result2))
      			{		
   					print "acl $row[name] $row[type] $row2[value]\n";    
    				}							
				}	   			
   			
				//Get ACL permission
				$query3 = "select type, access from squid_access_list where acl_name_s=\"$row[name]\" ";
   			$result3 = mysql_query($query3, $db);
   			$rowCheck3 = mysql_num_rows($result3);
   			if ($rowCheck3 > 0)
   			{
      			while ($row3 = mysql_fetch_array($result3))
      			{		
   					print "$row3[type] $row3[access] $row[name]\n";    
    				}							
				}
				print "\n";
   			
   		}  
    	}							
	}
	
	print "# Other Default regular Squid standard ACLs\n";
	print "acl manager proto cache_object\n";
	print "acl localhost src 127.0.0.1/32\n";
	print "acl to_localhost dst 127.0.0.0/8 0.0.0.0/32\n";
	print "\n";
	print "# Example rule allowing access from your local networks.\n";
	print "# Adapt to list your (internal) IP networks from where browsing\n";
	print "# should be allowed\n";
	print "acl localnet src 10.0.0.0/8    # RFC1918 possible internal network\n";
	print "acl localnet src 172.16.0.0/12    # RFC1918 possible internal network\n";
	print "acl localnet src 192.168.0.0/16    # RFC1918 possible internal network\n";
	print "\n";
	print "acl SSL_ports port 443\n";
	print "acl Safe_ports port 80        # http\n";
	print "acl Safe_ports port 21        # ftp\n";
	print "acl Safe_ports port 443        # https\n";
	print "acl Safe_ports port 70        # gopher\n";
	print "acl Safe_ports port 210        # wais\n";
	print "acl Safe_ports port 1025-65535    # unregistered ports\n";
	print "acl Safe_ports port 280        # http-mgmt\n";
	print "acl Safe_ports port 488        # gss-http\n";
	print "acl Safe_ports port 591        # filemaker\n";
	print "acl Safe_ports port 777        # multiling http\n";
	print "acl CONNECT method CONNECT\n";
	print "\n";
	print "http_access allow all\n";
	print "#------------------------------------------------------\n";	
}

function generate_http_accel($db)
{	
	print "\n# Squid HTTP Accelerator settings:\n";
	$query = "select httpd_accel_host, httpd_accel_port, httpd_accel_with_proxy, httpd_accel_single_host, httpd_accel_uses_host_header from squid_cfg where id=1 ";
   $result = mysql_query($query, $db);
   $rowCheck = mysql_num_rows($result);
   if ($rowCheck > 0)
   {
      while ($row = mysql_fetch_array($result))
      {	$httpd_accel_host = $row[httpd_accel_host];
      	$httpd_accel_port = $row[httpd_accel_port];
      	$httpd_accel_with_proxy = $row[httpd_accel_with_proxy];
      	$httpd_accel_single_host = $row[httpd_accel_single_host];
      	$httpd_accel_uses_host_header = $row[httpd_accel_uses_host_header];
   		if($httpd_accel_host!=NULL) print "httpd_accel_host $httpd_accel_host\n";
 			if($httpd_accel_port!=NULL) print "httpd_accel_port $httpd_accel_port\n";
 			if($httpd_accel_with_proxy!=NULL) print "httpd_accel_with_proxy $httpd_accel_with_proxy\n";
 			if($httpd_accel_single_host!=NULL) print "httpd_accel_single_host $httpd_accel_single_host\n";
 			if($httpd_accel_uses_host_header!=NULL) print "httpd_accel_uses_host_header $httpd_accel_uses_host_header\n";
    	}							
	}
	print "#------------------------------------------------------\n";	
} /* generate_http_accel */

?>