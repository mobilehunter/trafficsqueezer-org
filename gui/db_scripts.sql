CREATE TABLE profile (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
profile varchar(200) NOT NULL DEFAULT 'NULL',
username varchar(30) NOT NULL DEFAULT 'NULL',
password varchar(30) NOT NULL DEFAULT 'NULL',
firstname varchar(40) NOT NULL DEFAULT '',
lastname varchar(40) NOT NULL DEFAULT '',
db varchar(30) NOT NULL DEFAULT 'NULL',
language varchar(4) NOT NULL DEFAULT 'en',
color_id int(10) unsigned NOT NULL DEFAULT 1,
stats_history int(10) unsigned NOT NULL DEFAULT 60,
PRIMARY KEY (id)
);
insert into profile (id, username, password) values (1, "root","welcome");

CREATE TABLE color (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
box_color varchar(10) NOT NULL DEFAULT '',
box_color_hover varchar(10) NOT NULL DEFAULT '',
background_color varchar(10) NOT NULL DEFAULT '',
name varchar(10) NOT NULL DEFAULT '',
PRIMARY KEY (id)
);
insert into color (id, box_color, box_color_hover, background_color, name) values (1, "#FFD800","#F1CC00", "#F1F1F1", "Yellow");
insert into color (id, box_color, box_color_hover, background_color, name) values (2, "#CECE0E","#C0C00D", "#F1F1F1", "Green");
insert into color (id, box_color, box_color_hover, background_color, name) values (3, "#FF836A","#FF755D", "#F1F1F1", "Brick Red");
insert into color (id, box_color, box_color_hover, background_color, name) values (4, "#85C8FF","#55B4FF", "#F1F1F1", "Blue");

#
#mode: MODE_NONE, MODE_ROUTER, MODE_BRIDGE, MODE_LOCAL, MODE_ROUTER_LOCAL, MODE_SIMULATE
#
CREATE TABLE basic_config (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
mode varchar(35) NOT NULL DEFAULT 'MODE_NONE',
coal_en int(4) unsigned NOT NULL DEFAULT '0',
coalescing_protocol_dns_enable int(4) unsigned NOT NULL DEFAULT '0',
encrypt_enabled int(4) unsigned NOT NULL DEFAULT '0',
qos_enabled int(4) unsigned NOT NULL DEFAULT '0',
qos_wan_bandwidth int(4) unsigned NOT NULL DEFAULT '0',
qos_p0_bandwidth int(4) unsigned NOT NULL DEFAULT '0',
qos_p1_bandwidth int(4) unsigned NOT NULL DEFAULT '0',
qos_p2_bandwidth int(4) unsigned NOT NULL DEFAULT '0',
qos_p3_bandwidth int(4) unsigned NOT NULL DEFAULT '0',
qos_p4_bandwidth int(4) unsigned NOT NULL DEFAULT '0',
bridge_ip_addr varchar(20) NOT NULL DEFAULT '20.0.0.1',
bridge_subnet_msk varchar(20) NOT NULL DEFAULT '255.0.0.0',
br_forward_enable int(4) unsigned NOT NULL DEFAULT '0',
ip_forward_enable int(4) unsigned NOT NULL DEFAULT '0',
ip_forward_nat_enable int(4) unsigned NOT NULL DEFAULT '0',
r_ip_ntwrk_machine_en int(4) unsigned NOT NULL DEFAULT '0',
host_name varchar(20) NOT NULL DEFAULT 'aquarium',
filter_dns_enable int(4) unsigned NOT NULL DEFAULT '0',
PRIMARY KEY (id)
);
insert into basic_config (id,host_name) values (1,"aquarium");


#
#/proc/sys/net/ipv4 tcp optimization parameters
#
# tcp_congestion_control: cubic, reno, hybla, bic, westwood, vegas, htcp, scalable, yeah, illinois
#
CREATE TABLE tcp_optimize_config (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
tcp_timestamps int(12) unsigned NOT NULL DEFAULT '0',
tcp_sack int(12) unsigned NOT NULL DEFAULT '0',
tcp_dsack int(12) unsigned NOT NULL DEFAULT '0',
tcp_fack int(12) unsigned NOT NULL DEFAULT '0',
tcp_autocorking int(12) unsigned NOT NULL DEFAULT '1',
tcp_window_scaling int(4) unsigned NOT NULL DEFAULT '0',
ip_no_pmtu_disc int(4) unsigned NOT NULL DEFAULT '1',
tcp_ecn int(4) unsigned NOT NULL DEFAULT '0',
rmem_max int(12) unsigned NOT NULL DEFAULT '131071',
rmem_default int(12) unsigned NOT NULL DEFAULT '112640',
wmem_max int(12) unsigned NOT NULL DEFAULT '131071',
wmem_default int(12) unsigned NOT NULL DEFAULT '112640',
tcp_congestion_control varchar(12) NOT NULL DEFAULT 'cubic',
PRIMARY KEY (id)
);
insert into tcp_optimize_config (id) values (1);


#
# Filter-DNS Domain list
#
CREATE TABLE `filter_dns_list` (
`id` INT(4) UNSIGNED NOT NULL AUTO_INCREMENT,
`domain` VARCHAR(40) NOT NULL DEFAULT '',
`name` VARCHAR(40) NOT NULL DEFAULT '',
PRIMARY KEY (`id`),
UNIQUE INDEX `domain` (`domain`)
);

#nameserver list: /etc/resolv.conf
CREATE TABLE nameserver (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
nameserver_ip varchar(30) NOT NULL DEFAULT '',
PRIMARY KEY (id),
UNIQUE INDEX `nameserver_ip` (`nameserver_ip`)
);


#
# DPI Settings
#
CREATE TABLE dpi_config (
id int(4) unsigned NOT NULL AUTO_INCREMENT,
dpi_enable int(4) unsigned NOT NULL DEFAULT '0',
dpi_dns_request_enable int(4) unsigned NOT NULL DEFAULT '0',
dpi_http_access_enable int(4) unsigned NOT NULL DEFAULT '0',
dpi_pop_enable int(4) unsigned NOT NULL DEFAULT '0',
PRIMARY KEY (id)
);
insert into dpi_config (id) values (1);

#
#port name: none_eth0, em1, ....
#
CREATE TABLE port_config (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
port_lan_name varchar(8) NOT NULL DEFAULT 'none',
port_wan_name varchar(8) NOT NULL DEFAULT 'none',
port_lan_ip_addr varchar(20) NOT NULL DEFAULT '0.0.0.0',
port_wan_ip_addr varchar(20) NOT NULL DEFAULT '0.0.0.0',
port_lan_mac varchar(26) NOT NULL DEFAULT '',
port_wan_mac varchar(26) NOT NULL DEFAULT '',
port_bridge_ip_addr varchar(20) NOT NULL DEFAULT '0.0.0.0',
port_bridge_subnet_msk varchar(20) NOT NULL DEFAULT '0.0.0.0',
PRIMARY KEY (id)
);
insert into port_config (id) values (1);

#
# ifconfig -a -> store this updated info in this table. Delete any unknown/removed ports
# direction -> lan/wan
CREATE TABLE port_list (
name varchar(8) NOT NULL DEFAULT '',
ip_addr varchar(20) NOT NULL DEFAULT '0.0.0.0',
subnet_msk varchar(20) NOT NULL DEFAULT '0.0.0.0',
mac varchar(26) NOT NULL DEFAULT '',
direction varchar(26) NOT NULL DEFAULT '',
UNIQUE INDEX `name` (`name`)
);

#
# type: ipv4, ipv6
#
CREATE TABLE remote_subnet (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
type varchar(20) NOT NULL default 'ipv4',
network_id varchar(20) NOT NULL DEFAULT '0.0.0.0',
subnet_msk varchar(20) NOT NULL DEFAULT '0.0.0.0',
PRIMARY KEY (id)
);

#
# type: ipv4, ipv6
#
CREATE TABLE remote_ip_machine (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
type varchar(20) NOT NULL default 'ipv4',
ip_addr varchar(20) NOT NULL DEFAULT '0.0.0.0',
PRIMARY KEY (id)
);

#
# gateway_port: such as eth1, eth2, ...
#
CREATE TABLE static_network_route_table (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
type varchar(20) NOT NULL default 'ipv4',
network_id varchar(20) NOT NULL DEFAULT '0.0.0.0',
subnet_msk varchar(20) NOT NULL DEFAULT '0.0.0.0',
gateway varchar(20) NOT NULL DEFAULT '0.0.0.0',
gateway_port varchar(20) NOT NULL DEFAULT '',
PRIMARY KEY (id)
);


# forward_rule (iptable rules or firewall rules) 
# port_type: such as --destination-port, --source-port, --both ...
# rule_type: ACCEPT, DROP
# protocol: tcp, udp
#
CREATE TABLE forward_rule (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
protocol varchar(20) NOT NULL default 'tcp',
port_type varchar(26) NOT NULL DEFAULT '--both',
port_no int(8) unsigned NOT NULL DEFAULT '0',
rule_type varchar(10) NOT NULL DEFAULT 'DROP',
PRIMARY KEY (id)
);

# qos_rule
# port_type: such as --destination-port, --source-port, --both ...
# priority: 0, 1, 2, 3, 4
#
CREATE TABLE qos_rule (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
protocol varchar(20) NOT NULL default 'tcp',
port_type varchar(26) NOT NULL DEFAULT '--both',
port_no int(8) unsigned NOT NULL DEFAULT '0',
priority int(8) unsigned NOT NULL DEFAULT '0',
PRIMARY KEY (id)
);

#load in GB
CREATE TABLE stats_mem (
id int(32) unsigned NOT NULL auto_increment,
type int(10) unsigned NOT NULL default '0',
timestamp datetime default NULL,
total decimal(20,2) unsigned default '0.00',
used decimal(20,2) unsigned default '0.00',
PRIMARY KEY  (id)
);

CREATE TABLE stats_bandwidth (
id int(32) unsigned NOT NULL auto_increment,
type int(10) unsigned NOT NULL default '0',
timestamp datetime default NULL,
lan_bytes_per_sec decimal(20,3) unsigned default '0.000',
wan_bytes_per_sec decimal(20,3) unsigned default '0.000',
PRIMARY KEY  (id)
);

CREATE TABLE stats_filter_dns (
id int(32) unsigned NOT NULL auto_increment,
type int(10) unsigned NOT NULL default '0',
timestamp datetime default NULL,
lan_filter_dns_pkts int(8) unsigned NOT NULL DEFAULT '0',
wan_filter_dns_pkts int(8) unsigned NOT NULL DEFAULT '0',
lan_filter_dns_bytes_saved int(8) unsigned NOT NULL DEFAULT '0',
wan_filter_dns_bytes_saved int(8) unsigned NOT NULL DEFAULT '0',
PRIMARY KEY  (id)
);

CREATE TABLE stats_overall (
id int(32) unsigned NOT NULL auto_increment,
type int(10) unsigned NOT NULL default '0',
timestamp datetime default NULL,
lan_stats_pct int(20) default '0',
wan_stats_pct int(20) default '0',
lan_rx int(20) unsigned default '0',
lan_tx int(20) unsigned default '0',
lan_bytes_saved int(20) unsigned default '0',
wan_rx int(20) unsigned default '0',
wan_tx int(20) unsigned default '0',
wan_bytes_saved int(20) unsigned default '0',
PRIMARY KEY (id)
);

CREATE TABLE stats_coalescing (
id int(32) unsigned NOT NULL auto_increment,
type int(10) unsigned NOT NULL default '0',
timestamp datetime default NULL,
lan_stats_pct int(20) default '0',
wan_stats_pct int(20) default '0',
PRIMARY KEY  (id)
);


CREATE TABLE stats_ip_proto (
id int(32) unsigned NOT NULL auto_increment,
type int(10) unsigned NOT NULL default '0',
timestamp datetime default NULL,
l_tcp_pkt_cnt decimal(10,3) unsigned default '0.000',
l_udp_pkt_cnt decimal(10,3) unsigned default '0.000',
l_icmp_pkt_cnt decimal(10,3) unsigned default '0.000',
l_sctp_pkt_cnt decimal(10,3) unsigned default '0.000',
l_others_pkt_cnt decimal(10,3) unsigned default '0.000',
l_units_format varchar(6) default '-',
w_tcp_pkt_cnt decimal(10,3) unsigned default '0.000',
w_udp_pkt_cnt decimal(10,3) unsigned default '0.000',
w_icmp_pkt_cnt decimal(10,3) unsigned default '0.000',
w_sctp_pkt_cnt decimal(10,3) unsigned default '0.000',
w_others_pkt_cnt decimal(10,3) unsigned default '0.000',
w_units_format varchar(6) default '-',
PRIMARY KEY  (id)
);
	
	
CREATE TABLE stats_pkt_sizes (
id int(32) unsigned NOT NULL auto_increment,
type int(10) unsigned NOT NULL default '0',
timestamp datetime default NULL,
l_in_pkt_cnt_0_63 decimal(10,3) unsigned default '0.000',
l_out_pkt_cnt_0_63 decimal(10,3) unsigned default '0.000',
w_in_pkt_cnt_0_63 decimal(10,3) unsigned default '0.000',
w_out_pkt_cnt_0_63 decimal(10,3) unsigned default '0.000',
l_in_pkt_cnt_64_127 decimal(10,3) unsigned default '0.000',
l_out_pkt_cnt_64_127 decimal(10,3) unsigned default '0.000',
w_in_pkt_cnt_64_127 decimal(10,3) unsigned default '0.000',
w_out_pkt_cnt_64_127 decimal(10,3) unsigned default '0.000',
l_in_pkt_cnt_128_255 decimal(10,3) unsigned default '0.000',
l_out_pkt_cnt_128_255 decimal(10,3) unsigned default '0.000',
w_in_pkt_cnt_128_255 decimal(10,3) unsigned default '0.000',
w_out_pkt_cnt_128_255 decimal(10,3) unsigned default '0.000',
l_in_pkt_cnt_256_511 decimal(10,3) unsigned default '0.000',
l_out_pkt_cnt_256_511 decimal(10,3) unsigned default '0.000',
w_in_pkt_cnt_256_511 decimal(10,3) unsigned default '0.000',
w_out_pkt_cnt_256_511 decimal(10,3) unsigned default '0.000',
l_in_pkt_cnt_512_1023 decimal(10,3) unsigned default '0.000',
l_out_pkt_cnt_512_1023 decimal(10,3) unsigned default '0.000',
w_in_pkt_cnt_512_1023 decimal(10,3) unsigned default '0.000',
w_out_pkt_cnt_512_1023 decimal(10,3) unsigned default '0.000',
l_in_pkt_cnt_1024_above decimal(10,3) unsigned default '0.000',
l_out_pkt_cnt_1024_above decimal(10,3) unsigned default '0.000',
w_in_pkt_cnt_1024_above decimal(10,3) unsigned default '0.000',
w_out_pkt_cnt_1024_above decimal(10,3) unsigned default '0.000',
l_units_format varchar(6) default '-',
e_units_format varchar(6) default '-',
PRIMARY KEY  (id)
);
	
#DPI Logs
CREATE TABLE `dpi_http_access_log` (
	`id` INT(32) UNSIGNED NOT NULL AUTO_INCREMENT,
	`jiffies` INT(20) UNSIGNED ZEROFILL NULL DEFAULT NULL,
	`timestamp` DATETIME NULL DEFAULT NULL,
	`request_type` CHAR(1) NULL DEFAULT NULL COMMENT '//GET = G/POST = P',
	`src_ip` VARCHAR(20) NULL DEFAULT NULL COMMENT '//ASCII IP Address form',
	`dst_ip` VARCHAR(20) NULL DEFAULT NULL COMMENT '//ASCII IP Address form',
	`domain` VARCHAR(40) NULL DEFAULT NULL COMMENT '//www.abc.com (Host: )',
	`content` VARCHAR(90) NULL DEFAULT NULL COMMENT '//download.html in (http://www.abc.com/download.html) (or) URL without domain',
	`browser` VARCHAR(20) NULL DEFAULT NULL COMMENT '//firefox, ie, chrome',
	PRIMARY KEY (`id`),
	UNIQUE INDEX `jiffies` (`jiffies`, `domain`, `content`)
);


CREATE TABLE `dpi_dns_request_log` (
	`id` INT(32) UNSIGNED NOT NULL AUTO_INCREMENT,
	`jiffies` INT(20) UNSIGNED ZEROFILL NOT NULL,
	`timestamp` DATETIME NULL DEFAULT NULL,
	`request_type` CHAR(1) NULL DEFAULT NULL COMMENT '//GET = G/POST = P',
	`src_ip` VARCHAR(20) NULL DEFAULT NULL COMMENT '//ASCII IP Address form',
	`dst_ip` VARCHAR(20) NULL DEFAULT NULL COMMENT '//ASCII IP Address form',
	`domain` VARCHAR(40) NULL DEFAULT NULL COMMENT '//www.abc.com (Host: )',
	PRIMARY KEY (`id`),
	UNIQUE INDEX `jiffies` (`jiffies`, `domain`)
);


CREATE TABLE `dpi_pop_log` (
	`id` INT(32) UNSIGNED NOT NULL AUTO_INCREMENT,
	`jiffies` INT(20) UNSIGNED ZEROFILL NOT NULL,
	`timestamp` DATETIME NULL DEFAULT NULL,
	`src_ip` VARCHAR(20) NULL DEFAULT NULL COMMENT '//ASCII IP Address form',
	`dst_ip` VARCHAR(20) NULL DEFAULT NULL COMMENT '//ASCII IP Address form',
	`email_from` VARCHAR(20) NULL DEFAULT NULL COMMENT '//email from',
	`email_to` VARCHAR(20) NULL DEFAULT NULL COMMENT '//email to',
	`email_cc` VARCHAR(20) NULL DEFAULT NULL COMMENT '//email cc',
	`email_bcc` VARCHAR(20) NULL DEFAULT NULL COMMENT '//email bcc',
	`subject` VARCHAR(40) NULL DEFAULT NULL COMMENT '//subject',
	PRIMARY KEY (`id`),
	UNIQUE INDEX `jiffies` (`jiffies`, `email_from`, `email_to`, `subject`)
);

CREATE TABLE `dpi_user_alias` (
  `id` int(20) unsigned NOT NULL AUTO_INCREMENT,
  `cust_id` varchar(20) NOT NULL,
  `ip` varchar(20) NOT NULL,
  `mac` varchar(22) NOT NULL,
  `alias_user_name` varchar(40) NOT NULL,
  PRIMARY KEY (`id`)
);


CREATE TABLE kernel_jobs (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
kernel_job varchar(200) NOT NULL DEFAULT 'NULL',
PRIMARY KEY (id)
);

CREATE TABLE gui_jobs (
id int(10) unsigned NOT NULL AUTO_INCREMENT,
job varchar(500) NOT NULL DEFAULT 'NULL',
job_result varchar(6000) NOT NULL DEFAULT 'NULL',
job_pending int(3) unsigned default '1',
PRIMARY KEY (id)
);


CREATE TABLE command_output (
id int(10) unsigned NOT NULL,
command varchar(500) NOT NULL DEFAULT 'NULL',
output varchar(12000) NOT NULL DEFAULT 'NULL',
PRIMARY KEY (id)
);
insert into  command_output (id, command) values (1, "cat /proc/cpuinfo | grep \"processor\\|vendor_id\\|model\\ name\\|cpu\\ M\\|cache\\ size\" | sed 's/\\t//g' | sed 's/: /:/g' | cut -f 2 -d \":\" ");
insert into  command_output (id, command) values (2, "ps -aef");
insert into  command_output (id, command) values (3, "ifconfig -a");
#insert into  command_output (id, command) values (4, "netstat -t | grep -E '^tcp|^udp' | sed 's/    / /g' |  sed 's/  / /g'| sed 's/  / /g'| sed 's/ /,/g'  | cut -f 1,4,5 -d ',' ");
insert into  command_output (id, command) values (5, "netstat -l | grep -E '^tcp|^udp' | sed 's/    / /g' |  sed 's/  / /g'| sed 's/  / /g'| sed 's/ /,/g' | sed 's/:://g'  | sed 's/:/,/g' | cut -f 1,4,5 -d ',' |  sed 's/\\[\\]/\\[::\\]/g' ");
insert into  command_output (id, command) values (6, "arp |  sed 's/ [ \\t ]*/,/g' | awk 'FNR>1'");
insert into  command_output (id, command) values (7, "chkconfig --list | sed 's/\t/,/g' | sed 's/    //g' | sed 's/   //g' | sed 's/  //g' |  sed 's/  //g' | sed 's/:off/:x/g' | sed 's/:on/:o/g' | sed 's/0://g' | sed 's/1://g' |  sed 's/2://g' |  sed 's/3://g' |  sed 's/4://g' |  sed 's/5://g' |  sed 's/6://g' ");
insert into  command_output (id, command) values (8, "lsmod | cut -f1 -d' ' ");
insert into  command_output (id, command) values (9, "who -a");
insert into  command_output (id, command) values (10, "iptables -L");
insert into  command_output (id, command) values (11, "lspci");
insert into  command_output (id, command) values (12, "cat /etc/squid/squid.conf");
insert into  command_output (id, command) values (13, "route");
insert into  command_output (id, command) values (14, "cat /boot/grub2/grub.cfg");
insert into  command_output (id, command) values (15, "brctl show");

