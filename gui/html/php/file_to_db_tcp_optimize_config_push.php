<?php

//Read the TCP optimize settings in /proc config files and push this into DB

error_reporting(5);

$tcp_timestamps = `cat /proc/sys/net/ipv4/tcp_timestamps`;
$tcp_sack = `cat /proc/sys/net/ipv4/tcp_sack`;
$tcp_dsack = `cat /proc/sys/net/ipv4/tcp_dsack`;
$tcp_fack = `cat /proc/sys/net/ipv4/tcp_fack`;
$tcp_window_scaling = `cat /proc/sys/net/ipv4/tcp_window_scaling`;
$ip_no_pmtu_disc = `cat /proc/sys/net/ipv4/ip_no_pmtu_disc`;
$tcp_ecn = `cat /proc/sys/net/ipv4/tcp_ecn`;
$tcp_congestion_control = `cat /proc/sys/net/ipv4/tcp_congestion_control`;
$rmem_max = `cat /proc/sys/net/core/rmem_max`;
$rmem_default = `cat /proc/sys/net/core/rmem_default`;
$wmem_max = `cat /proc/sys/net/core/wmem_max`;
$wmem_default = `cat /proc/sys/net/core/wmem_default`;

$db = mysql_connect("localhost", "root", "welcome") or die ("Error connecting to database.");
mysql_select_db("aquarium", $db) or die ("Couldn't select the database.");
$query="";

$query = "update tcp_optimize_config set tcp_timestamps=$tcp_timestamps where id=1";
mysql_query($query, $db);

$query = "update tcp_optimize_config set tcp_sack=$tcp_sack where id=1";
mysql_query($query, $db);

$query = "update tcp_optimize_config set tcp_dsack=$tcp_dsack where id=1";
mysql_query($query, $db);

$query = "update tcp_optimize_config set tcp_fack=$tcp_fack where id=1";
mysql_query($query, $db);

$query = "update tcp_optimize_config set tcp_window_scaling=$tcp_window_scaling where id=1";
mysql_query($query, $db);

$query = "update tcp_optimize_config set ip_no_pmtu_disc=$ip_no_pmtu_disc where id=1";
mysql_query($query, $db);

$query = "update tcp_optimize_config set tcp_ecn=$tcp_ecn where id=1";
mysql_query($query, $db);

$query = "update tcp_optimize_config set tcp_congestion_control=$tcp_congestion_control where id=1";
mysql_query($query, $db);

$query = "update tcp_optimize_config set rmem_max=$rmem_max where id=1";
mysql_query($query, $db);

$query = "update tcp_optimize_config set rmem_default=$rmem_default where id=1";
mysql_query($query, $db);

$query = "update tcp_optimize_config set wmem_max=$wmem_max where id=1";
mysql_query($query, $db);

$query = "update tcp_optimize_config set wmem_default=$wmem_default where id=1";
mysql_query($query, $db);

mysql_close($db);
?>
