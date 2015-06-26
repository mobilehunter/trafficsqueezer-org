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
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter_ipv4.h>
#include <net/checksum.h>
#include <linux/route.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <linux/ctype.h>
#include <linux/gfp.h>
#include <net/trafficsqueezer/core.h>
#include <net/trafficsqueezer/dpi_core.h>
#include <net/trafficsqueezer/memreplace.h>
#include <net/trafficsqueezer/stats.h>
#include <net/trafficsqueezer/filter_dns.h>
#include <net/trafficsqueezer/dpi_dns.h>
int GROV_ts_dpi_dns_request_en	= TS_TRUE; EXPORT_SYMBOL(GROV_ts_dpi_dns_request_en);
dns_request_log_t *dns_request_logs; EXPORT_SYMBOL(dns_request_logs);
int dns_request_logs_current_position = -1; EXPORT_SYMBOL(dns_request_logs_current_position); //rotating log position in the array
static void init_dns_request_log(INOUT dns_request_log_t *dns_request_log)
{
	if(dns_request_log==NULL) return TS_FALSE;
	dns_request_log->jiffies = 0;
	dns_request_log->en = TS_FALSE;
	dns_request_log->domain[0] = 0x00;
	memset(dns_request_log->src_ip, 0x00, 4);
	memset(dns_request_log->dst_ip, 0x00, 4);
}

void init_dns_request_log_list(void)
{	int i=0;
	for(i=0; i<MAX_DPI_LOG_LINES; i++)
   {
   	init_dns_request_log(&dns_request_logs[i]);
   }
} 

static int dns_request_log_list_check_duplicate(IN dns_request_log_t *dns_request_log)
{
	int i=0;

	if(dns_request_logs_current_position==-1) return TS_FALSE;
	
	for(i=0; i<MAX_DPI_LOG_LINES; i++)
   {
   	if(dns_request_logs[i].en == TS_TRUE)
   	{
   		if(!memcmp(dns_request_logs[i].src_ip, dns_request_log->src_ip, 4))
   		{
   			if(!memcmp(dns_request_logs[i].dst_ip, dns_request_log->dst_ip, 4))
   			{
   				if(!strcmp(dns_request_logs[i].domain, dns_request_log->domain))
   				{
  						return TS_TRUE;
   				}
   			}
   		}
   	}
   }
   
	return TS_FALSE;
}

static void add_dns_request_log_in_list(IN dns_request_log_t *dns_request_log)
{	if(dns_request_log==NULL) return;
	if(dns_request_log_list_check_duplicate(dns_request_log)==TS_TRUE) return;
	//increment current pointer (if list is still empty this pointer should point '-1' )
	if(dns_request_logs_current_position<MAX_DPI_LOG_LINES) dns_request_logs_current_position++; else dns_request_logs_current_position=0;
	dns_request_logs[dns_request_logs_current_position].en = TS_TRUE;
	dns_request_logs[dns_request_logs_current_position].jiffies = jiffies;
	strcpy(dns_request_logs[dns_request_logs_current_position].domain, dns_request_log->domain);
	memcpy(dns_request_logs[dns_request_logs_current_position].src_ip, dns_request_log->src_ip, 4);
	memcpy(dns_request_logs[dns_request_logs_current_position].dst_ip, dns_request_log->dst_ip, 4);
}

int ts_parse_dpi_dns_request(IN BYTE *buff, IN size_t bufflen, OUT dns_request_log_t *dns_request_log)
{
	int i=0;
	int dns_request = 0; //0= GET, 1=POST
	BYTE *domain = dns_request_log->domain;  //get the parsed domain and store here.
	
	//Checking the type of the dns packet is DNS request !
	if((buff[2] & 0x80) == 0x00)
	{
		dns_request = 1;
		//printk("dns request\n");	
	}
	else
	{
		//printk("invalid dns packet or not DNS request type\n"); 
		return TS_FALSE;
	}
	
	//Check if the packet is too small ?
	if(bufflen<=20) { return TS_FALSE; }

	BYTE *dns_req_start = NULL;
	BYTE *dns_req_end = NULL;
   dns_req_start = (buff+12);
   for(i=0;i<(bufflen-(dns_req_start-buff));i++)
   {
   	if( dns_req_start[i] == 0x00)
    	{
    		dns_req_end = (dns_req_start+i); dns_req_end++; break;
    	}
    }

	//Check the domain extract is > 98 (DNS Protocol specifications) ? Too big domain name ?
	if( (dns_req_end-dns_req_start) > 98 ) { return TS_FALSE; }

	//Check the domain extract is <4 (DNS Protocol specifications) ? Too small domain name ?
	if( (dns_req_end-dns_req_start) <4 ) { return TS_FALSE; }


	//Now extract the domain name in the local buffer
	memcpy(domain, dns_req_start, (size_t)(dns_req_end-dns_req_start) );

	//Convert the DNS protocol domain name representation into end-user acscii type representation.
	//// Ex: 03www04abcd03com00 --> .www.abcd.com -> www.abcd.com
	BYTE *pos_domain = domain;
	int skip_count=0;
	for(i=0 ; i<strlen(domain) ; i++,pos_domain++)
	{
			if(skip_count==0)
			{
					skip_count=(int) *pos_domain;
					
					//Check whether this skip count is within limits ? !! Means not a valid DNS packet  !!
					if(  skip_count > (strlen(domain)-(i+1))  ) { return TS_FALSE; }
					domain[i] = '.';
					continue;
			}
			else
			{
				//do nothing just skip !
			   skip_count--;
			}
	}	

	//Remove the first "." character.
	//// Ex: .www.abcd.com -> www.abcd.com
	strcpy(domain, (domain+1));
	
	//Check now it contains only printable chars ? !!
	if(ts_found_printable_ascii(domain, strlen(domain), IS_DOMAIN)==0) { return TS_FALSE; }

	//Now finally we got a valid domain in a valid DNS packet !
	return TS_TRUE;
}

int ts_parse_dpi_dns_request_pkt(IN struct sk_buff *skb)
{	int ip_hdr_len = ip_hdrlen(skb);
	int udp_hdr_len = ts_get_udp_hdr_size(skb);
			
	//Check it is a real DNS or some bogus or unknown packet ?
	/// If so do not process it further !!
	if( (skb->len-ip_hdr_len-udp_hdr_len)<18) return TS_TRUE; //send true since this is DNS protocol !
			
	BYTE *pkt_buff = (skb->data+ip_hdr_len+udp_hdr_len);
	size_t pkt_buff_len = (skb->len-ip_hdr_len-udp_hdr_len);

	dns_request_log_t dns_request_log;
	init_dns_request_log(&dns_request_log);
	if(ts_parse_dpi_dns_request(pkt_buff, pkt_buff_len, &dns_request_log)==TS_TRUE)
   {	memcpy(dns_request_log.src_ip, ts_get_ip_source_ip_addr(skb), 4);
   	memcpy(dns_request_log.dst_ip, ts_get_ip_dest_ip_addr(skb), 4);
   	//Add or write to the global
   	spin_lock(&v_c_ts_dns_request_log_list_lock_v_c);
   	add_dns_request_log_in_list(&dns_request_log);
   	spin_unlock(&v_c_ts_dns_request_log_list_lock_v_c);
   	return TS_TRUE;
   }
	return TS_FALSE;
}