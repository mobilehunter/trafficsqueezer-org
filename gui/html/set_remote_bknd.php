<?php include('c/c_check_login.php'); include("c/c_db_access.php"); include('c/c_g_var_set.php'); error_reporting(5);

$r_ip_ntwrk_machine_en_before = $_POST['r_ip_ntwrk_machine_en_before'];
$r_ip_ntwrk_machine_en = $_POST['r_ip_ntwrk_machine_en'];
if($r_ip_ntwrk_machine_en==NULL)$r_ip_ntwrk_machine_en = 0;
if($r_ip_ntwrk_machine_en_before != $r_ip_ntwrk_machine_en)
{
   set_r_ip_ntwrk_machine_en($r_ip_ntwrk_machine_en, $query, $db);
}

$_operation = $_GET['operation'];
if($_operation==NULL) $_operation = $_POST['operation'];
$network_id = $_GET['network_id'];
if($network_id==NULL) $network_id=$_POST['network_id'];
$subnet_msk = $_GET['subnet_msk'];
if($subnet_msk==NULL) $subnet_msk=$_POST['subnet_msk'];

if($_operation=="remove_subnet")
{ set_del_r_ip_ntwrk_list_network_id($network_id, $query, $db); }
else if($_operation=="add_subnet")
{
	if (validate_ip_address($network_id)==false || validate_ip_address($subnet_msk)==false)
	{
	    print "<span style=\"font-size:10px;color:white;\">Error: In-valid Address !<br></font</span>";
	    $page_delay = 4;
	
	}
	else 
	{
   	set_add_r_ip_ntwrk_list_network_id($network_id, $subnet_msk, $query, $db);
	}
}


$_ip_addr = $_GET['ip_addr'];
if($_ip_addr==NULL) $_ip_addr = $_POST['ip_addr'];
if($_operation=="remove_machine")
{ set_del_r_r_ip_machine_list($_ip_addr, $query, $db); }
else if($_operation=="add_machine")
{
	if(validate_ip_address($_ip_addr)==false)
	{
    	print "<span style=\"font-size:10px;color:#333333;\">Error: In-valid IP Address !<br></span>";
    	$page_delay = 4;
	}
	else 
	{
   	set_add_r_ip_machine_list($_ip_addr, $query, $db);
	}
}

print "<meta HTTP-EQUIV=\"REFRESH\" content=\"".$page_delay."; url=remote.php\">";

function validate_ip_address($ip_addr)
{
    //first of all the format of the ip address is matched
    if (preg_match("/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/", $ip_addr))
    {
        //now all the intger values are separated
        $parts = explode(".", $ip_addr);
        //now we need to check each part can range from 0-255
        foreach ($parts as $ip_parts)
        {
            if (intval($ip_parts) > 255 || intval($ip_parts) < 0)
                return false; //if number is not within range of 0-255

        }
        return true;
    }
    else
        return false; //if format of ip address doesn't matches
}
?>