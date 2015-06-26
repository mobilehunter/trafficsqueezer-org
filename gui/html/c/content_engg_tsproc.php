<style type="text/css">
table.grid_style {border-width:1px;border-spacing:2px;border-style:ridge;border-color:#B6B6B6;border-collapse:collapse;background-color:white;}
table.grid_style th {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:12px;}
table.grid_style td {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:12px;}
#table_top_heading {background-color:gray;font-weight:bold;color:white;text-decoration:none;font-size:12px;}
</style>
<?php
$buf=`cat $file`;
if(strlen($buf)==0) { $buf = "<br><br><br>Not a TrafficSqueezer Kernel !\n"; }
print "<pre>$buf</pre>";
?>