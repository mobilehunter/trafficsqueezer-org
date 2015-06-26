/*
TRAFFICSQUEEZER provides dual licenses, designed to meet the usage and distribution requirements of different types of users.

GPLv2 License: Copyright (C) (2006-2014) Kiran Kankipati (kiran.kankipati@gmail.com) All Rights Reserved.
        
TrafficSqueezer is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License Version 2, and not any other version, as published by the Free Software Foundation. TrafficSqueezer is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.You should have received a copy of the GNU General Public License along with TrafficSqueezer; see the file COPYING. If not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

BSD License (2-clause license): Copyright (2006-2014) Kiran Kankipati. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY KIRAN KANKIPATI ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KIRAN KANKIPATI OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those of the authors and should not be interpreted as representing official policies, either expressed or implied, of Kiran Kankipati.

* This license is applicable exclusive to the TrafficSqueezer components. TrafficSqueezer may bundle or include other third-party open-source components. Kindly refer these component README and COPYRIGHT/LICENSE documents, released by its respective authors and project/module owners.
** For more details about Third-party components, you can also kindly refer TrafficSqueezer project website About page.
*/
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/ctype.h>
#include <linux/time.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <net/trafficsqueezer/core.h>
#include <net/trafficsqueezer/coal.h>
#include <net/trafficsqueezer/stats.h>
#include <net/trafficsqueezer/proc.h>
#include <net/trafficsqueezer/dpi_core.h>
#include <net/trafficsqueezer/filter_dns.h>
#include <net/trafficsqueezer/dpi_dns.h>
#include <net/trafficsqueezer/dpi_pop.h>
#include <net/trafficsqueezer/dpi_http.h>
#include <net/trafficsqueezer/templ.h>

static bool parse_string_to_ip_address(u8 *ip, char *buffer);
static void proc_int_var_set(BYTE *value, int *int_var, BYTE *int_var_name);

struct proc_dir_entry *ts_proc_dir;
struct proc_dir_entry *ts_proc_stats;
struct proc_dir_entry *ts_proc_config;
struct proc_dir_entry *ts_proc_io;
struct proc_dir_entry *ts_proc_dpi_dns_request;
struct proc_dir_entry *ts_proc_dpi_pop;
struct proc_dir_entry *ts_proc_dpi_http_access;

char *proc_buf;

#define PROCFS_MAX_SIZE 3048

static ssize_t ts_proc_io_write(struct file *fp, const char *buf, size_t len, loff_t * off)
{	if(len > PROCFS_MAX_SIZE) { return -EFAULT; }
   if(copy_from_user(proc_buf, buf, len)) { return -EFAULT; }
	if(proc_buf==NULL || len>80) { goto ts_proc_io_write_END; }
	*(proc_buf+len) = '\0'; len++; //add \0 at the end of buffer
	//Contents format: "<command>,<value>\n"
   BYTE *val=NULL;   //Pointer pointing value
	
	int i=0;
	int return_char_ctr = 0;

	for(i=0;i<len;i++)
	{	if(*(proc_buf+i)==',' && (i+1)<len) { val=(proc_buf+i+1); }
		if(*(proc_buf+i)==',') { *(proc_buf+i)='\0'; }
		if(*(proc_buf+i)=='\n') { *(proc_buf+i)='\0'; return_char_ctr++; }
	}
	if(return_char_ctr==0 || return_char_ctr>1) { goto ts_proc_io_write_END; }
	
	if(!strcmp(proc_buf, "pv_ts_lan_port_pv"))
	{	printk("@ ASSIGN_LAN [%s]\n", val);
		spin_lock(&ts_lan_port_lock);
		strcpy(G_ts_lan_port, val);
		spin_unlock(&ts_lan_port_lock);

		spin_lock(&ts_wan_port_lock);
		if(!strcmp(G_ts_wan_port, val)) { strcpy(G_ts_wan_port, "none"); }
		spin_unlock(&ts_wan_port_lock);
	}
	else if(!strcmp(proc_buf, "pv_ts_wan_port_pv"))
	{	printk("@ ASSIGN_WAN [%s]\n", val);
		spin_lock(&ts_wan_port_lock);
		strcpy(G_ts_wan_port, val);
		spin_unlock(&ts_wan_port_lock);
		
		spin_lock(&ts_lan_port_lock);
		if(!strcmp(G_ts_lan_port, val)) { strcpy(G_ts_lan_port, "none"); }
		spin_unlock(&ts_lan_port_lock);
	}
	else if(!strcmp(proc_buf, "pv_ts_ip_fwd_nat_en_pv")) { proc_int_var_set(val, &G_ts_ip_fwd_nat_en, proc_buf); }
   else if(!strcmp(proc_buf, "pv_ts_r_ip_ntwrk_machine_en_pv")) { proc_int_var_set(val, &G_ts_r_ip_ntwrk_machine_en, proc_buf); }
	else if(!strcmp(proc_buf, "pv_r_ip_ntwrk_list_add_pv"))
	{
		BYTE *network_id; //Pointer pointing command
      BYTE *subnet_msk; //Pointer pointing value

		//Parse network-id and subnet-mask
		//format: <network_id>:<subnet_msk>
		network_id = val;
		{
			int i=0;
			int pipe_ctr = 0;
			int value_len = strlen(val);
			for(i=0;i<value_len;i++)
			{
				if(*(val+i)==':' && (i+1)<value_len)	{	subnet_msk=(val+i+1);	}
				if(*(val+i)==':') { *(val+i)='\0'; pipe_ctr++; }
				if(*(val+i)=='\n') { *(val+i)='\0'; }
			}
			if(pipe_ctr==0 || pipe_ctr>1) { goto ts_proc_io_write_END; }
		}
		printk("n:%s|m:%s|\n", network_id, subnet_msk);
		//Parse ip-address format and load
		u8 network_id_octets[4];
		u8 subnet_msk_octets[4];
		if(parse_string_to_ip_address(network_id_octets, network_id) && parse_string_to_ip_address(subnet_msk_octets, subnet_msk))
		{	int i;
			//Check duplicates ?	
			for(i=0; i<MAX_REMOTE_LIST; i++)
     		{
				if(r_ip_ntwrk_list[i].en==TS_TRUE)
				{	if(match_ip(r_ip_ntwrk_list[i].network_id, network_id_octets)) { goto ts_proc_io_write_END; }
				}
			}

			for(i=0; i<MAX_REMOTE_LIST; i++)
     		{
				if(r_ip_ntwrk_list[i].en==TS_FALSE)
				{	r_ip_ntwrk_list[i].network_id[0]=network_id_octets[0];
					r_ip_ntwrk_list[i].network_id[1]=network_id_octets[1];
					r_ip_ntwrk_list[i].network_id[2]=network_id_octets[2];	
					r_ip_ntwrk_list[i].network_id[3]=network_id_octets[3];
					r_ip_ntwrk_list[i].subnet_msk[0]=subnet_msk_octets[0];
					r_ip_ntwrk_list[i].subnet_msk[1]=subnet_msk_octets[1];
					r_ip_ntwrk_list[i].subnet_msk[2]=subnet_msk_octets[2];
					r_ip_ntwrk_list[i].subnet_msk[3]=subnet_msk_octets[3];
     	     	   r_ip_ntwrk_list[i].en=TS_TRUE;
					goto ts_proc_io_write_END;
				}
			}
		}
	}
	else if(!strcmp(proc_buf, "pv_r_ip_ntwrk_list_del_pv"))
	{	BYTE *network_id; //Pointer pointing command
		network_id = val;
		printk("value: %s\n", val);
		BYTE network_id_octets[4];
		printk("n:%s|\n", network_id);
		//Parse ip-address format and load
		if(parse_string_to_ip_address(network_id_octets, network_id))
		{	int i;
			//Check for a match ?	
			for(i=0; i<MAX_REMOTE_LIST; i++)
     	   {
				if(r_ip_ntwrk_list[i].en==TS_TRUE)
				{
					if(match_ip(r_ip_ntwrk_list[i].network_id, network_id_octets))
					{	r_ip_ntwrk_list[i].en=TS_FALSE;
						goto ts_proc_io_write_END;
					}
				}
			}
		}
	}
	else if(!strcmp(proc_buf, "pv_r_ip_machine_list_add_pv"))
	{	BYTE ip_octets[4];
		printk("n:%s|\n", val);
		//Parse ip-address format and load
		if(parse_string_to_ip_address(ip_octets, val))
		{	int i;
			//Check for a match ?	
			for(i=0;i<MAX_REMOTE_LIST;i++)
     		{
				if(r_ip_machine_list[i].en==TS_TRUE)
				{
					if(match_ip(r_ip_machine_list[i].ipaddr, ip_octets)) { goto ts_proc_io_write_END; }
				}
			}
				
			for(i=0; i<MAX_REMOTE_LIST; i++)
     		{
				if(r_ip_machine_list[i].en==TS_FALSE)
				{
					r_ip_machine_list[i].ipaddr[0] = ip_octets[0];
					r_ip_machine_list[i].ipaddr[1] = ip_octets[1];
					r_ip_machine_list[i].ipaddr[2] = ip_octets[2];	
					r_ip_machine_list[i].ipaddr[3] = ip_octets[3];
     	     	   r_ip_machine_list[i].en=TS_TRUE;
					r_ip_machine_list[i].ignore_ip=TS_FALSE;
					goto ts_proc_io_write_END;
				}
			}
		}
	}
	else if(!strcmp(proc_buf, "pv_r_ip_machine_list_del_pv"))
	{
		BYTE *ip_addr; //Pointer pointing command
		ip_addr = val;
		printk("value: %s\n", val);
		BYTE ip_octets[4];
		printk("n:%s|\n", ip_addr);
		//Parse ip-address format and load
		if(parse_string_to_ip_address( ip_octets, ip_addr))
		{	int i;
			//Check for a match ?	
			for(i=0; i<MAX_REMOTE_LIST; i++)
     		{
				if(r_ip_machine_list[i].en==TS_TRUE)
				{
					if(match_ip(r_ip_machine_list[i].ipaddr, ip_octets))
					{	r_ip_machine_list[i].en=TS_FALSE;
						goto ts_proc_io_write_END;
					}
				}
			}
		}
	}
   else if(!strcmp(proc_buf, "pv_ts_mode_pv")) 
   { 
   	if(!strcmp(val, "MODE_NONE")) G_ts_mode=MODE_NONE;
   	else if(!strcmp(val, "MODE_ROUTER")) G_ts_mode=MODE_ROUTER;
   	else if(!strcmp(val, "MODE_BRIDGE")) G_ts_mode=MODE_BRIDGE;
   	else if(!strcmp(val, "MODE_LOCAL")) G_ts_mode=MODE_LOCAL;
   	else if(!strcmp(val, "MODE_ROUTER_LOCAL")) G_ts_mode=MODE_ROUTER_LOCAL;
   	else if(!strcmp(val, "MODE_SIMULATE")) G_ts_mode=MODE_SIMULATE;
   }
	else if(!strcmp(proc_buf, "pv_ts_coal_proto_dns_en_pv")) { proc_int_var_set(val, &G_ts_coal_proto_dns_en, proc_buf); }
	else if(!strcmp(proc_buf, "pv_ts_filter_dns_en_pv")) { proc_int_var_set(val, &G_ts_filter_dns_en, proc_buf); }
	else if(!strcmp(proc_buf, "pv_ts_filter_dns_add_pv")) { printk("add dns-domain = %s\n", val); add_ts_dns_domain_in_list(val); }
	else if(!strcmp(proc_buf, "pv_ts_filter_dns_del_pv")) { printk("del dns-domain = %s\n", val); del_ts_dns_domain_in_list(val); }
ts_proc_io_write_END:
	return len;
}

static ssize_t ts_proc_stats_read(struct file *fp, char *buf, size_t len, loff_t * off)
{	static int finished=0; if(finished) {finished=0;return 0;} finished=1;
	
	spin_lock(&ts_lan_stats_lock);
	sprintf(buf, "overall|%u|%u", ts_oper_stats.lan_rx_bytes, ts_oper_stats.lan_tx_bytes);

	sprintf((buf+100), "ip_proto|%u|%u|%u|%u|%u", \
	 ts_lan_proto_stats.ts_ip_proto_stats.tcp_pkt_cnt, \
	 ts_lan_proto_stats.ts_ip_proto_stats.udp_pkt_cnt, \
	 ts_lan_proto_stats.ts_ip_proto_stats.icmp_pkt_cnt, \
	 ts_lan_proto_stats.ts_ip_proto_stats.sctp_pkt_cnt, \
	 ts_lan_proto_stats.ts_ip_proto_stats.others_pkt_cnt);

	sprintf((buf+300), "pkt_sizes|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u", \
	 ts_lan_pkt_sizes_stats.in_pkt_cnt_0_63, ts_lan_pkt_sizes_stats.out_pkt_cnt_0_63, \
	 ts_lan_pkt_sizes_stats.in_pkt_cnt_64_127, ts_lan_pkt_sizes_stats.out_pkt_cnt_64_127, \
	 ts_lan_pkt_sizes_stats.in_pkt_cnt_128_255, ts_lan_pkt_sizes_stats.out_pkt_cnt_128_255, \
	 ts_lan_pkt_sizes_stats.in_pkt_cnt_256_511, ts_lan_pkt_sizes_stats.out_pkt_cnt_256_511, \
	 ts_lan_pkt_sizes_stats.in_pkt_cnt_512_1023, ts_lan_pkt_sizes_stats.out_pkt_cnt_512_1023, \
	 ts_lan_pkt_sizes_stats.in_pkt_cnt_1024_above, ts_lan_pkt_sizes_stats.out_pkt_cnt_1024_above);
	 
	ts_oper_stats.lan_rx_bytes = (BYTEx4)0;
	ts_oper_stats.lan_tx_bytes = (BYTEx4)0;
	memset( &ts_lan_pkt_sizes_stats, 0x00, sizeof(ts_pkt_sizes_stats_t));
	memset( &ts_lan_proto_stats, 0x00, sizeof(ts_proto_stats_t));
	spin_unlock(&ts_lan_stats_lock);

	spin_lock(&ts_wan_stats_lock);
	sprintf(buf, "%s|%u|%u\n", buf, ts_oper_stats.wan_rx_bytes, ts_oper_stats.wan_tx_bytes);

	sprintf((buf+100), "%s|%u|%u|%u|%u|%u\n", (buf+100), \
	 ts_wan_proto_stats.ts_ip_proto_stats.tcp_pkt_cnt, \
	 ts_wan_proto_stats.ts_ip_proto_stats.udp_pkt_cnt, \
	 ts_wan_proto_stats.ts_ip_proto_stats.icmp_pkt_cnt, \
	 ts_wan_proto_stats.ts_ip_proto_stats.sctp_pkt_cnt, \
	 ts_wan_proto_stats.ts_ip_proto_stats.others_pkt_cnt);
	 
	sprintf((buf+300), "%s|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u\n", (buf+300), \
	 ts_wan_pkt_sizes_stats.in_pkt_cnt_0_63, ts_wan_pkt_sizes_stats.out_pkt_cnt_0_63, \
	 ts_wan_pkt_sizes_stats.in_pkt_cnt_64_127, ts_wan_pkt_sizes_stats.out_pkt_cnt_64_127, \
	 ts_wan_pkt_sizes_stats.in_pkt_cnt_128_255, ts_wan_pkt_sizes_stats.out_pkt_cnt_128_255, \
	 ts_wan_pkt_sizes_stats.in_pkt_cnt_256_511, ts_wan_pkt_sizes_stats.out_pkt_cnt_256_511, \
	 ts_wan_pkt_sizes_stats.in_pkt_cnt_512_1023, ts_wan_pkt_sizes_stats.out_pkt_cnt_512_1023, \
	 ts_wan_pkt_sizes_stats.in_pkt_cnt_1024_above, ts_wan_pkt_sizes_stats.out_pkt_cnt_1024_above );
	 
	ts_oper_stats.wan_rx_bytes = (BYTEx4)0;
	ts_oper_stats.wan_tx_bytes = (BYTEx4)0;
	memset( &ts_wan_pkt_sizes_stats, 0x00, sizeof(ts_pkt_sizes_stats_t));
	memset( &ts_wan_proto_stats, 0x00, sizeof(ts_proto_stats_t));
	spin_unlock(&ts_wan_stats_lock);
	
	sprintf(buf, "%s%s%s%s", buf, (buf+100), (buf+200), (buf+300));

	spin_lock(&ts_coal_stats_lock);
   sprintf(buf, "%scoal|%u|%u|%u|%u\n", buf, 
    ts_coal_stats.lan_rx_pkts, ts_coal_stats.lan_tx_pkts, ts_coal_stats.wan_rx_pkts, ts_coal_stats.wan_tx_pkts );
   memset( &ts_coal_stats, 0x00, sizeof(ts_coal_stats_t));
	spin_unlock(&ts_coal_stats_lock);

   sprintf(buf, "%sfilter_dns|%u|%u|%u|%u\n", buf, 
   ts_filter_dns_stats.lan_filter_dns_pkts, ts_filter_dns_stats.wan_filter_dns_pkts,
   ts_filter_dns_stats.lan_filter_dns_bytes_saved, ts_filter_dns_stats.wan_filter_dns_bytes_saved );
   memset( &ts_filter_dns_stats, 0x00, sizeof(ts_filter_dns_stats_t));
  
 return strlen(buf);
} /* ts_proc_stats_read */

static ssize_t ts_proc_config_read(struct file *fp, char *buf, size_t len, loff_t * off)
{	int i=0;
	static int finished=0; if(finished) {finished=0;return 0;} finished=1;
	strcpy(buf, "");

	spin_lock(&ts_lan_port_lock);
	sprintf(buf, "%sport mode %s lan\n", buf, G_ts_lan_port);
	spin_unlock(&ts_lan_port_lock);
		
	spin_lock(&ts_wan_port_lock);
	sprintf(buf, "%sport mode %s wan\n", buf, G_ts_wan_port);
	spin_unlock(&ts_wan_port_lock);
	
	if(G_ts_mode==MODE_NONE) sprintf(buf, "%smode none\n", buf);
	else if(G_ts_mode==MODE_ROUTER) sprintf(buf, "%smode router\n", buf);
	else if(G_ts_mode==MODE_BRIDGE) sprintf(buf, "%smode bridge\n", buf);
	else if(G_ts_mode==MODE_LOCAL) sprintf(buf, "%smode local\n", buf);
	else if(G_ts_mode==MODE_ROUTER_LOCAL) sprintf(buf, "%smode router-local\n", buf);
	else if(G_ts_mode==MODE_SIMULATE) sprintf(buf, "%smode simulate\n", buf);

	if(GROV_ts_coal_en) sprintf(buf, "%scoalescing enable\n", buf); else sprintf(buf, "%scoalescing disable\n", buf);
	if(G_ts_coal_proto_dns_en) sprintf(buf, "%scoalescing protocol dns enable\n", buf); else sprintf(buf, "%scoalescing protocol dns disable\n", buf);
	sprintf(buf, "%scoalescing bucket-timer %d\n", buf, GROV_ts_coal_bucket_timer_delay);
	sprintf(buf, "%scoalescing bucket-size %d\n", buf, GROV_ts_coal_bucket_size);

	if(G_ts_ip_fwd_nat_en) sprintf(buf, "%srouting nat enable\n", buf); else sprintf(buf, "%srouting nat disable\n", buf);
	if(GROV_ts_dpi_en) sprintf(buf, "%sdpi enable\n", buf); else sprintf(buf, "%sdpi disable\n", buf);
  	if(GROV_ts_dpi_dns_request_en) sprintf(buf, "%sdpi dns-request enable\n", buf); else sprintf(buf, "%sdpi dns-request disable\n", buf);
  	if(GROV_ts_dpi_http_access_en) sprintf(buf, "%sdpi http-access enable\n", buf); else sprintf(buf, "%sdpi http-access disable\n", buf);
	if(GROV_ts_dpi_pop_en) sprintf(buf, "%sdpi pop enable\n", buf); else sprintf(buf, "%sdpi pop disable\n", buf);
	if(G_ts_filter_dns_en) sprintf(buf, "%sdns block-domain enable\n", buf); else sprintf(buf, "%sdns block-domain disable\n", buf);
	
	for(i=0;i<MAX_DNS_DOMAINS;i++)
	{
		if(dns_domains[i].en)
		{ sprintf(buf, "%sdns add block-domain %s\n", buf, dns_domains[i].string_domain); }
	}

	if(G_ts_r_ip_ntwrk_machine_en) sprintf(buf, "%sremote-subnet-machine enable\n", buf); else sprintf(buf, "%sremote-subnet-machine disable\n", buf);
	
	for(i=0;i<MAX_REMOTE_LIST;i++)
   {
      if(r_ip_ntwrk_list[i].en)
      {	sprintf(buf, "%sremote-subnet add %d.%d.%d.%d %d.%d.%d.%d\n", buf, \
			 r_ip_ntwrk_list[i].network_id[0], r_ip_ntwrk_list[i].network_id[1], r_ip_ntwrk_list[i].network_id[2], r_ip_ntwrk_list[i].network_id[3], \
			 r_ip_ntwrk_list[i].subnet_msk[0], r_ip_ntwrk_list[i].subnet_msk[1], r_ip_ntwrk_list[i].subnet_msk[2], r_ip_ntwrk_list[i].subnet_msk[3] );
		}
		if(r_ip_machine_list[i].en)
      {	sprintf(buf, "%sremote-machine add %d.%d.%d.%d\n", buf, \
			 r_ip_machine_list[i].ipaddr[0], r_ip_machine_list[i].ipaddr[1], r_ip_machine_list[i].ipaddr[2], r_ip_machine_list[i].ipaddr[3] );
		}
	}

	sprintf(buf, "%s#templ_generic_count:%d - total:%d - free:%d\n", buf, ts_templ_generic_count, MAX_TS_TEMPL_GENERIC, MAX_TS_TEMPL_GENERIC-ts_templ_generic_count);
	sprintf(buf, "%s#templ_common_count:%d - total:%d - free:%d\n", buf, ts_templ_common_count, MAX_TS_PKT_TEMPL_COMMON, MAX_TS_PKT_TEMPL_COMMON-ts_templ_common_count);
	sprintf(buf, "%s#templ_http_count:%d - total:%d - free:%d\n", buf, ts_templ_http_count, MAX_TS_TEMPL_HTTP, MAX_TS_TEMPL_HTTP-ts_templ_http_count);
	sprintf(buf, "%s#templ_dns_count:%d - total:%d - free:%d\n", buf, ts_templ_dns_count, MAX_TS_TEMPL_DNS, MAX_TS_TEMPL_DNS-ts_templ_dns_count);
	sprintf(buf, "%s#templ_telnet_count:%d - total:%d - free:%d\n", buf, ts_templ_telnet_count, MAX_TS_TEMPL_TELNET, MAX_TS_TEMPL_TELNET-ts_templ_telnet_count);
	sprintf(buf, "%s#templ_imap_count:%d - total:%d - free:%d\n", buf, ts_templ_imap_count, MAX_TS_TEMPL_IMAP, MAX_TS_TEMPL_IMAP-ts_templ_imap_count);
	sprintf(buf, "%s#templ_mapi_count:%d - total:%d - free:%d\n", buf, ts_templ_mapi_count, MAX_TS_TEMPL_MAPI, MAX_TS_TEMPL_MAPI-ts_templ_mapi_count);
	sprintf(buf, "%s#templ_ftp_count:%d - total:%d - free:%d\n", buf, ts_templ_ftp_count, MAX_TS_TEMPL_FTP, MAX_TS_TEMPL_FTP-ts_templ_ftp_count);
	sprintf(buf, "%s#templ_nfs_count:%d - total:%d - free:%d\n", buf, ts_templ_nfs_count, MAX_TS_TEMPL_NFS, MAX_TS_TEMPL_NFS-ts_templ_nfs_count);
	sprintf(buf, "%s#templ_mysql_count:%d - total:%d - free:%d\n", buf, ts_templ_mysql_count, MAX_TS_TEMPL_MYSQL, MAX_TS_TEMPL_MYSQL-ts_templ_mysql_count);
   sprintf(buf, "%s#templ_pgsql_count:%d - total:%d - free:%d\n", buf, ts_templ_pgsql_count, MAX_TS_TEMPL_PGSQL, MAX_TS_TEMPL_PGSQL-ts_templ_pgsql_count);
   sprintf(buf, "%s#templ_sql_count:%d - total:%d - free:%d\n", buf, ts_templ_sql_count, MAX_TS_TEMPL_SQL, MAX_TS_TEMPL_SQL-ts_templ_sql_count);
   sprintf(buf, "%s#templ_mssql_count:%d - total:%d - free:%d\n", buf, ts_templ_mssql_count, MAX_TS_TEMPL_MSSQL, MAX_TS_TEMPL_MSSQL-ts_templ_mssql_count);
   sprintf(buf, "%s#templ_ssh_count:%d - total:%d - free:%d\n", buf, ts_templ_ssh_count, MAX_TS_TEMPL_SSH, MAX_TS_TEMPL_SSH-ts_templ_ssh_count);
   sprintf(buf, "%s#templ_ssl_count:%d - total:%d - free:%d\n", buf, ts_templ_ssl_count, MAX_TS_TEMPL_SSL, MAX_TS_TEMPL_SSL-ts_templ_ssl_count);
   sprintf(buf, "%s#templ_pop_count:%d - total:%d - free:%d\n", buf, ts_templ_pop_count, MAX_TS_TEMPL_POP, MAX_TS_TEMPL_POP-ts_templ_pop_count);
   sprintf(buf, "%s#templ_smtp_count:%d - total:%d - free:%d\n", buf, ts_templ_smtp_count, MAX_TS_TEMPL_SMTP, MAX_TS_TEMPL_SMTP-ts_templ_smtp_count);
   sprintf(buf, "%s#http_templ_dict_count:%d - total:%d - free:%d\n", buf, ts_http_templ_dict_count, MAX_TS_HTTP_TEMPL_DICT, MAX_TS_HTTP_TEMPL_DICT-ts_http_templ_dict_count);
   sprintf(buf, "%s#templ_ica_count:%d - total:%d - free:%d\n", buf, ts_templ_ica_count, MAX_TS_TEMPL_ICA, MAX_TS_TEMPL_ICA-ts_templ_ica_count);
   sprintf(buf, "%s#templ_rdp_count:%d - total:%d - free:%d\n", buf, ts_templ_ica_count, MAX_TS_TEMPL_RDP, MAX_TS_TEMPL_RDP-ts_templ_ica_count);
   sprintf(buf, "%s#templ_spice_count:%d - total:%d - free:%d\n", buf, ts_templ_spice_count, MAX_TS_TEMPL_SPICE, MAX_TS_TEMPL_SPICE-ts_templ_spice_count);
   sprintf(buf, "%s#templ_voip_count:%d - total:%d - free:%d\n", buf, ts_templ_voip_count, MAX_TS_TEMPL_VOIP, MAX_TS_TEMPL_VOIP-ts_templ_voip_count);
 	sprintf(buf, "%s#templ_sip_count:%d - total:%d - free:%d\n", buf, ts_templ_sip_count, MAX_TS_TEMPL_SIP, MAX_TS_TEMPL_SIP-ts_templ_sip_count);
   sprintf(buf, "%s#templ_h323_count:%d - total:%d - free:%d\n", buf, ts_templ_h323_count, MAX_TS_TEMPL_H323, MAX_TS_TEMPL_H323-ts_templ_h323_count);
   sprintf(buf, "%s#templ_ldap_count:%d - total:%d - free:%d\n", buf, ts_templ_ldap_count, MAX_TS_TEMPL_LDAP, MAX_TS_TEMPL_LDAP-ts_templ_ldap_count);
   sprintf(buf, "%s#templ_krb_count:%d - total:%d - free:%d\n", buf, ts_templ_krb_count, MAX_TS_TEMPL_KRB, MAX_TS_TEMPL_KRB-ts_templ_krb_count);
   sprintf(buf, "%s#templ_smb_count:%d - total:%d - free:%d\n", buf, ts_templ_smb_count, MAX_TS_TEMPL_SMB, MAX_TS_TEMPL_SMB-ts_templ_smb_count);
   sprintf(buf, "%s#templ_ssdp_count:%d - total:%d - free:%d\n", buf, ts_templ_ssdp_count, MAX_TS_TEMPL_SSDP, MAX_TS_TEMPL_SSDP-ts_templ_ssdp_count);
	
	return strlen(buf);
} /* ts_proc_config_read */

static ssize_t ts_proc_dpi_dns_request_read(struct file *fp, char *buf, size_t len, loff_t * off)
{	int i=0;
	static int finished=0; if(finished) {finished=0;return 0;} finished=1;
	strcpy(buf, "");
	spin_lock(&v_c_ts_dns_request_log_list_lock_v_c);
	if(dns_request_logs_current_position!=-1)
	{	
		for(i=0; i<MAX_DPI_LOG_LINES; i++)
   	{
         if(dns_request_logs[i].en)
         {
         	//jiffy, domain, source_ip, dest_ip
         	if(dns_request_logs_current_position==i) sprintf(buf, "%s[%d],", buf, i); else sprintf(buf, "%s%d,", buf, i);
         	
         	sprintf(buf, "%s%lu,%s,%d.%d.%d.%d,%d.%d.%d.%d\n", buf, \
         	 dns_request_logs[i].jiffies, dns_request_logs[i].domain, \
         	 dns_request_logs[i].src_ip[0], dns_request_logs[i].src_ip[1], dns_request_logs[i].src_ip[2], dns_request_logs[i].src_ip[3], \
         	 dns_request_logs[i].dst_ip[0], dns_request_logs[i].dst_ip[1], dns_request_logs[i].dst_ip[2], dns_request_logs[i].dst_ip[3] );
         	
         	//After consumption now delete/empty this log line.
         	dns_request_logs[i].en=TS_FALSE;	
         }
   	}

   	//Reset the current position (i.e entire array is consumed/emptied during read/consumption)
   	dns_request_logs_current_position=-1;
   }
   spin_unlock(&v_c_ts_dns_request_log_list_lock_v_c);
	return strlen(buf);
} /* ts_proc_dpi_dns_request_read */

static ssize_t ts_proc_dpi_pop_read(struct file *fp, char *buf, size_t len, loff_t * off)
{	int i=0;
	static int finished=0; if(finished) {finished=0;return 0;} finished=1;
	strcpy(buf, "");
	spin_lock(&v_c_ts_pop_log_list_lock_v_c);
	if(pop_logs_current_position!=-1)
	{
		for(i=0; i<MAX_DPI_LOG_LINES; i++)
   	{
         if(pop_logs[i].en)
         {
         	//jiffy, domain, source_ip, dest_ip
         	if(pop_logs_current_position==i) sprintf(buf, "%s[%d],", buf, i); else sprintf(buf, "%s%d,", buf, i);
         	
         	sprintf(buf, "%s%lu,%s,%s,%s,%s,%s,%d.%d.%d.%d,%d.%d.%d.%d\n", buf, \
         	 pop_logs[i].jiffies, pop_logs[i].from, pop_logs[i].to, pop_logs[i].cc, pop_logs[i].bcc, pop_logs[i].subject, \
         	 pop_logs[i].src_ip[0], pop_logs[i].src_ip[1], pop_logs[i].src_ip[2], pop_logs[i].src_ip[3], \
         	 pop_logs[i].dst_ip[0], pop_logs[i].dst_ip[1], pop_logs[i].dst_ip[2], pop_logs[i].dst_ip[3] );
         		
         	//After consumption now delete/empty this log line.
         	pop_logs[i].en=TS_FALSE;
         }
   	}
   	
   	//Reset the current position (i.e entire array is consumed/emptied during read/consumption)
   	pop_logs_current_position=-1;
   }
   spin_unlock(&v_c_ts_pop_log_list_lock_v_c);
	return strlen(buf);
} /* ts_proc_dpi_pop_read */

static ssize_t ts_proc_dpi_http_access_read(struct file *fp, char *buf, size_t len, loff_t * off)
{	int i=0;
	static int finished=0; if(finished) {finished=0;return 0;} finished=1;
	strcpy(buf, "");
	spin_lock(&v_c_ts_http_access_log_list_lock_v_c);
	if(http_access_logs_current_position!=-1)
	{
		for(i=0; i<MAX_DPI_LOG_LINES; i++)
   		{
         	if(http_access_logs[i].en)
         	{
         		//jiffy, domain, source_ip, dest_ip
         		if(http_access_logs_current_position==i) sprintf(buf, "%s[%d],", buf, i); else sprintf(buf, "%s%d,", buf, i);
         	
         		sprintf(buf, "%s%lu,%s,%s,%s,%d.%d.%d.%d,%d.%d.%d.%d,%c\n", buf, \
         		http_access_logs[i].jiffies, http_access_logs[i].domain, http_access_logs[i].content, http_access_logs[i].browser,  \
         		http_access_logs[i].src_ip[0], http_access_logs[i].src_ip[1], http_access_logs[i].src_ip[2], http_access_logs[i].src_ip[3], \
         		http_access_logs[i].dst_ip[0], http_access_logs[i].dst_ip[1], http_access_logs[i].dst_ip[2], http_access_logs[i].dst_ip[3], \
         		http_access_logs[i].request_type );
         		
         		//After consumption now delete/empty this log line.
         		http_access_logs[i].en=TS_FALSE;
         	}
   		}
   		//Reset the current position (i.e entire array is consumed/emptied during read/consumption)
   		http_access_logs_current_position=-1;
   }
   spin_unlock(&v_c_ts_http_access_log_list_lock_v_c);

	return strlen(buf);
} /* ts_proc_dpi_http_access_read */
 
static struct file_operations ts_proc_config_fops = { .owner=THIS_MODULE, .read=ts_proc_config_read, };
static struct file_operations ts_proc_io_fops = { .owner=THIS_MODULE, .write=ts_proc_io_write, };
static struct file_operations ts_proc_stats_fops = { .owner=THIS_MODULE, .read=ts_proc_stats_read, };
static struct file_operations ts_proc_dpi_dns_request_fops = { .owner=THIS_MODULE, .read=ts_proc_dpi_dns_request_read, };
static struct file_operations ts_proc_dpi_pop_fops = { .owner=THIS_MODULE, .read=ts_proc_dpi_pop_read, };
static struct file_operations ts_proc_dpi_http_access_fops = { .owner=THIS_MODULE, .read=ts_proc_dpi_http_access_read, };

void ts_init_proc(void)
{ proc_buf=kmalloc( sizeof(u8)*PROCFS_MAX_SIZE, GFP_DMA | GFP_KERNEL); if(proc_buf==NULL) { printk("proc_buf alloc failed!\n"); }
	
  ts_proc_dir=proc_mkdir( proc_dir_name, NULL);
  ts_proc_stats=proc_create(proc_file_stats_name, 0444, ts_proc_dir, &ts_proc_stats_fops); if(ts_proc_stats==NULL) { printk(KERN_ALERT "Error: Could not initialize %s\n", proc_file_stats_name);}
  ts_proc_config=proc_create(proc_file_config_name, 0444, ts_proc_dir, &ts_proc_config_fops); if(ts_proc_config==NULL) {	printk(KERN_ALERT "Error: Could not initialize %s\n", proc_file_config_name);}
  ts_proc_io=proc_create(proc_file_io_name, 0222, ts_proc_dir, &ts_proc_io_fops); if(ts_proc_io==NULL) { printk(KERN_ALERT "Error: Could not initialize %s\n", proc_file_io_name);}
  ts_proc_dpi_dns_request=proc_create(proc_file_dpi_dns_request_name, 0444, ts_proc_dir, &ts_proc_dpi_dns_request_fops); if(ts_proc_dpi_dns_request==NULL) { printk(KERN_ALERT "Error: Could not initialize %s\n", proc_file_dpi_dns_request_name); }
  ts_proc_dpi_pop=proc_create(proc_file_dpi_pop_name, 0444, ts_proc_dir, &ts_proc_dpi_pop_fops); if(ts_proc_dpi_pop==NULL) { printk(KERN_ALERT "Error: Could not initialize %s\n", proc_file_dpi_pop_name);}
  ts_proc_dpi_http_access=proc_create(proc_file_dpi_http_access_name, 0444, ts_proc_dir, &ts_proc_dpi_http_access_fops); if(ts_proc_dpi_http_access==NULL) {printk(KERN_ALERT "Error: Could not initialize %s\n", proc_file_dpi_http_access_name);}
}

static bool parse_string_to_ip_address(u8 *ip, char *buffer)
{
	char *start = buffer;
	char temp[30];
	int temp_ptr = 0;
	int dot_count = 0;
	
	if(buffer==NULL) return false;
	if(ip==NULL) return false;

	//contains 3 "." ?
	{	dot_count = 0;
		while( *start!='\0' && *start!='\n' )
		{
			if(*start=='.') { dot_count++; }
			start++;
		}
		if(dot_count!=3) return false;
	}

	//Now parse into stats 
	start = buffer;
	temp[0] = '\0';
	temp_ptr = 0;
	dot_count = 0;
	while( *start!='\0' && *start!='\n' )
	{
		if( (*start)!='.' )
		{	temp[temp_ptr] = *start;
			temp_ptr++;
			temp[temp_ptr] = '\0';
		}
		else
		{
			switch(dot_count)
			{
				case 0: ip[0] = (u8) simple_strtoul(temp, NULL, 10); break;
				case 1: ip[1] = (u8) simple_strtoul(temp, NULL, 10); break;
				case 2: ip[2] = (u8) simple_strtoul(temp, NULL, 10); break;
			}
			temp_ptr=0; temp[0]='\0';
			dot_count++;
		}
		start++;
	}
	ip[3] = (u8) simple_strtoul(temp, NULL, 10);
	printk("parse_string_to_ip_address: %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
	return true;
}

void proc_int_var_set(BYTE *value, int *int_var, BYTE *int_var_name)
{	unsigned int value_int=simple_strtoul(value,NULL,10);
	if((*int_var)==value_int || (value_int<0 || value_int>9)) { return; }
	printk("BEFORE: %s = %d\n", int_var_name, (*int_var));
	(*int_var) = value_int;
	printk("AFTER: %s = %d\n", int_var_name, (*int_var));
}
