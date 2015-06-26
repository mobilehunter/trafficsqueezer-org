<?php //Read the DB and execute the frequently used command, so that system status is syncd in DB
error_reporting(5); include("/var/www/html/c/c_db_access.php");

function update_port($db, $port)
{
	//get ip, subnet, mac and update in table
	$ip_addr = ` ifconfig $port | grep "inet " | sed 's/   / /g' | sed 's/  / /g' | sed 's/  / /g'|sed 's/ //g'|sed 's/netmask/,/g'|sed 's/inet//g'  | sed 's/destination/,/g' | sed 's/broadcast/,/g' | cut -f1 -d,`;
	$subnet = ` ifconfig $port | grep "inet " | sed 's/   / /g' | sed 's/  / /g' | sed 's/  / /g'|sed 's/ //g'|sed 's/netmask/,/g'|sed 's/inet//g'  | sed 's/destination/,/g' | sed 's/broadcast/,/g' | cut -f2 -d,`;
	$mac = `ifconfig $port | grep "ether " | sed 's/   / /g' | sed 's/  / /g' | sed 's/  / /g'|sed 's/ //g'|sed 's/ether//g'|sed 's/txqueuelen/,/g' | cut -f1 -d,`;
	$ether_type = `ifconfig $port | grep "ether " | sed 's/   / /g' | sed 's/  / /g' | sed 's/  / /g'|sed 's/ //g'|sed 's/ether//g'|sed 's/txqueuelen/,/g' | cut -f2 -d,`;
	$ip_addr = chop($ip_addr);
	$subnet = chop($subnet);
	$mac = chop($mac);
	$query = "update port_list set ip_addr=\"$ip_addr\" where name=\"$port\"";
	print "$query \n";
	mysql_query($query, $db);
	$query = "update port_list set subnet_msk=\"$subnet\" where name=\"$port\"";
	print "$query \n";
	mysql_query($query, $db);
	$query = "update port_list set mac=\"$mac\" where name=\"$port\"";
	print "$query \n";
	mysql_query($query, $db);
	$found_in_db=true;
	
	$query2 = "select port_lan_name, port_wan_name from port_config";
	$result2=mysql_query($query2, $db);
	if(mysql_num_rows($result2)>0)
	{ while($row2 = mysql_fetch_array($result2))
	  {
			$port_lan_name = $row2['port_lan_name'];
			$port_wan_name = $row2['port_wan_name'];
			if($port_lan_name==$port)
			{
				$query3 = "update port_list set direction=\"LAN\" where name=\"$port\"";
				print "$query3 \n";
				mysql_query($query3, $db);
			}
			else if($port_wan_name==$port)
			{
				$query3 = "update port_list set direction=\"WAN\" where name=\"$port\"";
				print "$query3 \n";
				mysql_query($query3, $db);
			}
			else 
			{
				$query3 = "update port_list set direction=\"None\" where name=\"$port\"";
				print "$query3 \n";
				mysql_query($query3, $db);
			}
	  }
	}
}

//$get_ports = `ifconfig | grep 'flags' |  sed 's/   / /g' | sed 's/  / /g' | sed 's/  / /g'|sed 's/ //g' | cut -d ':' -f 1`;
$get_ports = `cat /proc/net/dev | grep ":" | cut -d: -f1| sed 's/   / /g'| sed 's/  //g' | sed 's/ //g'`;
$get_ports = chop($get_ports);
$ports = explode("\n", $get_ports);
foreach($ports as $port)
{	if($port==NULL || $port=="lo") continue;
 	$found_in_db=false;
 	//check if this port is there, if so then update its details, else populate in DB
 	
 	$query = "select name from port_list";
	$result=mysql_query($query, $db);
	if(mysql_num_rows($result)>0)
	{ while($row = mysql_fetch_array($result))
		{
			$name =  $row['name'];
			if($name==$port)
			{
				update_port($db, $port);
			}
		}
	}
	if($found_in_db==false)
	{
		$query = "insert into port_list (name) values (\"$port\")";
		print "$query \n";
		mysql_query($query, $db);
		update_port($db, $port);
	}

}

//delete any stray old entries which are no more in device
$query = "select name from port_list";
	$result=mysql_query($query, $db);
	if(mysql_num_rows($result)>0)
	{ while($row = mysql_fetch_array($result))
		{
			$name =  $row['name'];
			$found=false;
			 foreach($ports as $port)
 			 {	if($port==NULL || $port=="lo") continue;
 			 	if($name==$port) $found=true;
			 }
			if($found==false)
			{
				$query3 = "delete from port_list where name=\"$name\"";
				print "$query3 \n";
				mysql_query($query3, $db);
			}
		}
	}
mysql_close($db);
?>