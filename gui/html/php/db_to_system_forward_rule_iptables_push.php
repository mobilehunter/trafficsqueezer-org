<?php
//Read the firewall (forward rule) iptables settings in DB and push into /proc files.

error_reporting(5);

$db = mysql_connect("localhost", "root", "welcome") or die ("Error connecting to database.");
mysql_select_db("aquarium", $db) or die ("Couldn't select the database.");
$query = "select protocol, port_type, port_no, rule_type from forward_rule ";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
	while($row = mysql_fetch_array($result))
	{
			$protocol = $row['protocol'];
			$port_type = $row['port_type'];
			$port_no = $row['port_no'];
			$rule_type = $row['rule_type'];
			
			if($port_type=="--both")
			{
				//for SPORT
				system("iptables -I FORWARD -p $protocol -s 0/0 -d 0/0 --source-port $port_no -j $rule_type ");
		  
		 		//for DPORT
		 		system("iptables -I FORWARD -p $protocol -s 0/0 -d 0/0 --destination-port $port_no -j $rule_type ");
			}
			else
			{
		 		system("iptables -I FORWARD -p $protocol -s 0/0 -d 0/0 $port_type $port_no -j $rule_type ");
			}
	}
}
mysql_close($db);

?>
