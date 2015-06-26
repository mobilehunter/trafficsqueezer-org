<?php

function set_mode($value, $query, $db)
{
	$query = "insert into kernel_jobs (kernel_job) values (\"pv_ts_mode_pv,$value\")";
   mysql_query($query, $db);    
	$query = "update basic_config set mode=\"$value\" where id=1 ";
   $result=mysql_query($query, $db);
}

function set_r_ip_ntwrk_machine_en($value, $query, $db)
{
	$query = "insert into kernel_jobs (kernel_job) values (\"pv_ts_r_ip_ntwrk_machine_en_pv,$value\")";
   mysql_query($query, $db);
   $query = "update basic_config set r_ip_ntwrk_machine_en=$value where id=1";
   mysql_query($query, $db);
}

function set_add_r_ip_ntwrk_list_network_id($network_id, $subnet_msk, $query, $db)
{
	$query = "insert into kernel_jobs (kernel_job) values (\"pv_r_ip_ntwrk_list_add_pv,$network_id".":"."$subnet_msk\")";
   mysql_query($query, $db);
   $query = "insert into remote_subnet (type, network_id, subnet_msk) values (\"ipv4\", \"$network_id\", \"$subnet_msk\" )";
   mysql_query($query, $db);
}

function set_del_r_ip_ntwrk_list_network_id($value, $query, $db)
{
	$query = "insert into kernel_jobs (kernel_job) values (\"pv_c_r_ip_ntwrk_list_del_pv_c,$value\")";
   mysql_query($query, $db);
   $query = "delete from remote_subnet where network_id=\"$value\"";
   mysql_query($query, $db);
}

function set_add_r_ip_machine_list($_ip_addr, $query, $db)
{
	$query = "insert into kernel_jobs (kernel_job) values (\"pv_r_ip_machine_list_add_pv,$_ip_addr\")";
   mysql_query($query, $db);
   $query = "insert into remote_ip_machine (type, ip_addr) values (\"ipv4\", \"$_ip_addr\")";
   mysql_query($query, $db);
}

function set_del_r_r_ip_machine_list($_ip_addr, $query, $db)
{
	$query = "insert into kernel_jobs (kernel_job) values (\"pv_r_ip_machine_list_del_pv,$_ip_addr\")";
   mysql_query($query, $db);
   $query = "delete from remote_ip_machine where ip_addr=\"$_ip_addr\"";
   mysql_query($query, $db);
}


//Port Settings
function get_port_ip_addr($port, $query, $db)
{
	$query = "select ip_addr from port_list where name=\"$port\"";
	$result=mysql_query($query, $db);
	if(mysql_num_rows($result)>0)
	{ while($row = mysql_fetch_array($result))
		{
			return $row['ip_addr'];
		}
	}
	return NULL;
}

function get_port_wan_name($query, $db)
{
	$query = "select port_wan_name from port_config where id=1";
	$result=mysql_query($query, $db);
	if(mysql_num_rows($result)>0)
	{ while($row = mysql_fetch_array($result))
		{
			return $row['port_wan_name'];
		}
	}
	return NULL;
}

function get_port_lan_name($query, $db)
{
	$query = "select port_lan_name from port_config where id=1";
	$result=mysql_query($query, $db);
	if(mysql_num_rows($result)>0)
	{ while($row = mysql_fetch_array($result))
		{
			return $row['port_lan_name'];
		}
	}
	return NULL;
}

function update_port_list_direction($query, $db)
{
	$query = "select name from port_list";
	$result=mysql_query($query, $db);
	if(mysql_num_rows($result)>0)
	{ while($row = mysql_fetch_array($result))
		{
			$name = $row['name'];
			$query2 = "select port_lan_name, port_wan_name  from port_config";
			$result2=mysql_query($query2, $db);
			if(mysql_num_rows($result2)>0)
			{ while($row2 = mysql_fetch_array($result2))
				{
					$port_lan_name = $row2['port_lan_name'];
					$port_wan_name = $row2['port_wan_name'];
					if($name==$port_lan_name)
					{
						$query = "update port_list set direction=\"LAN\" where name=\"$name\"";
						mysql_query($query, $db);
					}
					else if($name==$port_wan_name)
					{
						$query = "update port_list set direction=\"WAN\" where name=\"$name\"";
						mysql_query($query, $db);
					}
					else 
					{
						$query = "update port_list set direction=\"None\" where name=\"$name\"";
						mysql_query($query, $db);
					}
				}
			}
		}
	}
	return NULL;
}

function set_port_wan_ip_addr($port_ip, $query, $db)
{
 	$query = "update port_config set port_wan_ip_addr=\"$port_ip\" where id=1";
	mysql_query($query, $db);
}

function set_port_lan_ip_addr($port_ip, $query, $db)
{	
 	$query = "update port_config set port_lan_ip_addr=\"$port_ip\" where id=1";
	mysql_query($query, $db);
}

function set_port_wan_name($port, $query, $db)
{
	$query = "insert into kernel_jobs (kernel_job) values (\"pv_ts_wan_port_pv,$port\")";
   mysql_query($query, $db);
   $query = "update port_config set port_wan_name=\"$port\" where id=1";
   mysql_query($query, $db);
   
 	if($port=="none") { set_port_wan_ip_addr("0.0.0.0", $query, $db); }
   else
   { $ip_addr = get_port_ip_addr($port, $query, $db);
     set_port_wan_ip_addr($ip_addr, $query, $db);
   
     if(get_port_lan_name($query, $db)==$port) 
     {
   	 set_port_lan_name("none", $query, $db);
     }
   }
   update_port_list_direction($query, $db);
}

function set_port_lan_name($port, $query, $db)
{
	$query = "insert into kernel_jobs (kernel_job) values (\"pv_ts_lan_port_pv,$port\")";
   mysql_query($query, $db);
   $query = "update port_config set port_lan_name=\"$port\" where id=1";
   mysql_query($query, $db);
   
 	if($port=="none") { set_port_lan_ip_addr("0.0.0.0", $query, $db); }
   else
   {  $ip_addr = get_port_ip_addr($port, $query, $db);
   	set_port_lan_ip_addr($ip_addr, $query, $db);
   	
		if(get_port_wan_name($query, $db)==$port) 
   	{
   		set_port_wan_name("none", $query, $db);
   	}
   }
   update_port_list_direction($query, $db);
}

function set_port($port, $direction, $query, $db)
{	$port_lan_name = get_port_lan_name($query, $db);
	$port_wan_name = get_port_wan_name($query, $db);

	if($direction=="LAN")
	{	
		set_port_lan_name($port, $query, $db);
	}
	else if($direction=="WAN")
	{	
		set_port_wan_name($port, $query, $db);
	}
	else if($direction=="None")
	{	
		if($port==$port_lan_name)
		{
			set_port_lan_name("none", $query, $db);	
		}
		else if($port==$port_wan_name)
		{
			set_port_wan_name("none", $query, $db);	
		}
	}
}

//Bridging
function activate_bridge($query, $db)
{	
	$query = "select mode,bridge_ip_addr, bridge_subnet_msk from basic_config where id=1";
	$result=mysql_query($query, $db);
	if(mysql_num_rows($result)>0)
	{ while($row=mysql_fetch_array($result))
		{	$mode = $row['mode'];
			$bridge_ip_addr = $row['bridge_ip_addr'];
			$bridge_subnet_msk = $row['bridge_subnet_msk'];
		}
	}

   $port_wan_name = get_port_wan_name($query, $db);
   $port_lan_name = get_port_lan_name($query, $db);
   if($port_wan_name!="none" && $port_lan_name!="none")
   {
	   if($mode=="MODE_BRIDGE")
	   {	
	   	$query = "insert into gui_jobs (job) values (\"brctl addbr tsbridge\")";
	   	mysql_query($query, $db); 
	 		$query = "insert into gui_jobs (job) values (\"brctl stp tsbridge off\")";
	   	mysql_query($query, $db);
	   	$query = "insert into gui_jobs (job) values (\"brctl addif tsbridge $port_wan_name\")";
	   	mysql_query($query, $db);
	   	$query = "insert into gui_jobs (job) values (\"brctl addif tsbridge $port_lan_name\")";
	   	mysql_query($query, $db);
	   	$query = "insert into gui_jobs (job) values (\"ifconfig $port_wan_name 0.0.0.0\")";
	   	mysql_query($query, $db);
	   	$query = "insert into gui_jobs (job) values (\"ifconfig $port_lan_name 0.0.0.0\")";
	   	mysql_query($query, $db);
	   	
	   	if($bridge_ip_addr!=NULL && $bridge_subnet_msk!=NULL)
	   	{$query = "insert into gui_jobs (job) values (\"ifconfig tsbridge $bridge_ip_addr netmask $bridge_subnet_msk up\")";}
	   	else {$query = "insert into gui_jobs (job) values (\"ifconfig tsbridge up\")";}
	   	mysql_query($query, $db);
	   }
	   else 
	   {	$query = "insert into gui_jobs (job) values (\"brctl delif tsbridge $port_wan_name\")";
	   	mysql_query($query, $db);
	   	$query = "insert into gui_jobs (job) values (\"brctl delif tsbridge $port_lan_name\")";
	   	mysql_query($query, $db);
	   	$query = "insert into gui_jobs (job) values (\"ifconfig tsbridge down\")";
	   	mysql_query($query, $db);
	   	$query = "insert into gui_jobs (job) values (\"brctl delbr tsbridge\")";
	   	mysql_query($query, $db);
	  	}
  }
  else 
  {  //port names perhaps not set properly, but remove bridging device
	  $query = "insert into gui_jobs (job) values (\"ifconfig tsbridge down\")";
	  mysql_query($query, $db);
	  $query = "insert into gui_jobs (job) values (\"brctl delbr tsbridge\")";
	  mysql_query($query, $db);
  }
} /* activate_bridge */

//Routing
function activate_router($query, $db)
{
   $query = "select mode from basic_config where id=1";
	$result=mysql_query($query, $db);
	if(mysql_num_rows($result)>0)
	{ while($row=mysql_fetch_array($result))
		{	$mode = $row['mode'];
		}
	}
	
	$port_wan_name = get_port_wan_name($query, $db);
   $port_lan_name = get_port_lan_name($query, $db);
	if($mode=="MODE_ROUTER"||$mode=="MODE_ROUTER_LOCAL")
	{
	   $query = "insert into gui_jobs (job) values (\"iptables -F\")";
	   mysql_query($query, $db);
	   
   	if($port_wan_name!="none")
   	{
   		$query = "insert into gui_jobs (job) values (\"iptables -I FORWARD -i $port_wan_name -j ACCEPT\")";
	   	mysql_query($query, $db);
	 	}
	 	if($port_lan_name!="none")
   	{
   		$query = "insert into gui_jobs (job) values (\"iptables -I FORWARD -i $port_lan_name -j ACCEPT\")";
	   	mysql_query($query, $db);
	 	}
	 	$query = "insert into gui_jobs (job) values (\"iptables -I INPUT -j ACCEPT\")";
	   mysql_query($query, $db);
      $query = "insert into gui_jobs (job) values (\"iptables -I OUTPUT -j ACCEPT\")";
	   mysql_query($query, $db);
      $query = "insert into gui_jobs (job) values (\"echo 1 > /proc/sys/net/ipv4/ip_forward\")";
	   mysql_query($query, $db);
	}
	else 
	{
	   $query = "insert into gui_jobs (job) values (\"echo 0 > /proc/sys/net/ipv4/ip_forward\")";
	   mysql_query($query, $db);
	}
} /* activate_router */

function set_filter_dns_enable($value, $query, $db)
{  $query = "insert into kernel_jobs (kernel_job) values (\"pv_ts_filter_dns_en_pv,$value\")";
   mysql_query($query, $db);
   $query = "update basic_config set filter_dns_enable=$value where id=1";
   mysql_query($query, $db);
}

?>
