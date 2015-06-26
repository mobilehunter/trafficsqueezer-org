<style type="text/css">
#overalloptimization_pct { width:920px;height:140px;background-color:white;}
#overalloptimization_bytes_saved { width:920px;height:140px;background-color:white;}
#overalloptimization_lan { width:920px;height:140px;background-color:white;}
#overalloptimization_wan { width:920px;height:140px;background-color:white;}
</style>

<script src="c/flot/jquery.js"></script>
<script src="c/flot/excanvas.js"></script>
<script src="c/flot/jquery.flot.js"></script>
<script src="c/flot/jquery.flot.time.js"></script>

<?php
print '<script type="text/javascript">
 $(document).ready(function() {';

include("/var/www/html/c/c_db_access.php"); error_reporting(5);
session_start(); $username = $_SESSION['username'];
$query = "select stats_history from profile where username='$username'";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{  while($row = mysql_fetch_array($result))
   { $stats_history = $row['stats_history']; }
}

$query_condition=" where timestamp>=DATE_SUB(NOW(),INTERVAL $stats_history MINUTE) and type=0";
$output="";
$query = "select UNIX_TIMESTAMP(timestamp)*1000 timestamp, lan_stats_pct, wan_stats_pct, lan_rx, lan_tx, lan_bytes_saved, wan_rx, wan_tx, wan_bytes_saved from stats_overall $query_condition";

$count=0;
$lan_overall_pct_output="";
$wan_overall_pct_output="";
$lan_overall_bytes_saved_output="";
$wan_overall_bytes_saved_output="";
$overall_lan_rx_output="";
$overall_lan_tx_output="";
$overall_wan_rx_output="";
$overall_wan_tx_output="";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
	while($row = mysql_fetch_array($result))
 {
 	  if($count>0) 
 	  { $lan_overall_pct_output.=",";
 	  	 $wan_overall_pct_output.=",";
 	  	 $lan_overall_bytes_saved_output.=",";
		 $wan_overall_bytes_saved_output.=",";
		 $overall_lan_rx_output.=",";
		 $overall_lan_tx_output.=",";
	    $overall_wan_rx_output.=",";
		 $overall_wan_tx_output.=",";
 	  }


	  $timestamp = $row['timestamp'];
	  $lan_stats_pct = $row['lan_stats_pct'];
	  $wan_stats_pct = $row['wan_stats_pct'];
	  $lan_rx = $row['lan_rx'];
	  $lan_tx = $row['lan_tx'];
	  $lan_bytes_saved = $row['lan_bytes_saved'];
	  $wan_rx = $row['wan_rx'];
	  $wan_tx = $row['wan_tx'];
	  $wan_bytes_saved = $row['wan_bytes_saved'];
	  $count++;

	  $lan_overall_pct_output.="[$timestamp,$lan_stats_pct]";
	  $wan_overall_pct_output.="[$timestamp,$wan_stats_pct]";
	  $lan_overall_bytes_saved_output.="[$timestamp,$lan_bytes_saved]";
	  $wan_overall_bytes_saved_output.="[$timestamp,$wan_bytes_saved]";
	  $overall_lan_rx_output.="[$timestamp,$lan_rx]";
	  $overall_lan_tx_output.="[$timestamp,$lan_tx]";
	  $overall_wan_rx_output.="[$timestamp,$wan_rx]";
	  $overall_wan_tx_output.="[$timestamp,$wan_tx]";
 }
}
print 'var lan_overall_pct = ['.$lan_overall_pct_output.'];'."\n";
print 'var wan_overall_pct = ['.$wan_overall_pct_output.'];'."\n";

print 'var lan_overall_bytes_saved = ['.$lan_overall_bytes_saved_output.'];'."\n";
print 'var wan_overall_bytes_saved = ['.$wan_overall_bytes_saved_output.'];'."\n";

print 'var overall_lan_rx = ['.$overall_lan_rx_output.'];'."\n";
print 'var overall_lan_tx = ['.$overall_lan_tx_output.'];'."\n";
print 'var overall_wan_rx = ['.$overall_wan_rx_output.'];'."\n";
print 'var overall_wan_tx = ['.$overall_wan_tx_output.'];'."\n";

print 'var overalloptimization_pct_data = [
    {
        label: "LAN -> WAN",
        data: lan_overall_pct,fill: 1.0,
        color: "rgba(150,150,150,0.4)",
    },
    {
        label: "WAN -> LAN",
        data: wan_overall_pct,fill: 1.0,
        color: "rgba(255,92,0,0.4)",
    }
    ];';
    
print 'var overalloptimization_bytes_saved_data = [
    {
        label: "LAN -> WAN",
        data: lan_overall_bytes_saved,fill: 1.0,
        color: "rgba(150,150,150,0.4)",
    },
    {
        label: "WAN -> LAN",
        data: wan_overall_bytes_saved,fill: 1.0,
        color: "rgba(255,92,0,0.4)",
    }
    ];';

print 'var overalloptimization_lan_data = [
    {
        label: "LAN Rx",
        data: overall_lan_rx,fill: 1.0,
        color: "rgba(150,150,150,0.4)",
    },
    {
        label: "LAN Tx",
        data: overall_lan_tx,fill: 1.0,
        color: "rgba(255,92,0,0.4)",
    }
    ];';
    
    
print 'var overalloptimization_wan_data = [
    {
        label: "WAN Rx",
        data: overall_wan_rx,fill: 1.0,
        color: "rgba(150,150,150,0.4)",
    },
    {
        label: "WAN Tx",
        data: overall_wan_tx,fill: 1.0,
        color: "rgba(255,92,0,0.4)",
    }
    ];';
    
    
$options = '{ xaxis: { mode: "time",timeformat: "%d/%b %H:%M",timezone: "browser" },
         grid: { borderWidth: {top: 1, right: 1, bottom: 1, left: 1}, borderColor: {top:"#888", bottom:"#888", left:"#888", right:"#888"} },
         series: { lines: { show:true, lineWidth:0, fill:true }, shadowSize:0},
         lines: {show:true,steps:false }
       }';

print '$.plot($("#overalloptimization_pct"), overalloptimization_pct_data,'.$options.');';
print '$.plot($("#overalloptimization_bytes_saved"), overalloptimization_bytes_saved_data,'.$options.');';
print '$.plot($("#overalloptimization_lan"), overalloptimization_lan_data,'.$options.');';
print '$.plot($("#overalloptimization_wan"), overalloptimization_wan_data,'.$options.');';
print '});';
print '</script>';
?>
<center>Overall Savings %</center>
<div id="overalloptimization_pct"></div>
<br>
<center>Overall Bytes Saved (KB)</center>
<div id="overalloptimization_bytes_saved"></div>
<br>
<center>Overall Optimization LAN - Bytes(KB)</center>
<div id="overalloptimization_lan"></div>
<br>
<center>Overall Optimization WAN - Bytes (KB)</center>
<div id="overalloptimization_wan"></div>