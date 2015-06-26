<?php error_reporting(5);
$db = mysql_connect("localhost", "root", "welcome") or die ("Error connecting to database.");
mysql_select_db("ts", $db) or die ("Couldn't select the database.");
?>
