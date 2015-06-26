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
#include <net/trafficsqueezer/dpi_http.h>

int GROV_ts_dpi_http_access_en	= TS_TRUE; EXPORT_SYMBOL(GROV_ts_dpi_http_access_en);
http_access_log_t *http_access_logs; EXPORT_SYMBOL(http_access_logs);
int http_access_logs_current_position = -1; EXPORT_SYMBOL(http_access_logs_current_position); //rotating log position in the array
static void init_http_access_log(http_access_log_t *http_access_log)
{
	if(http_access_log==NULL) return;
	http_access_log->jiffies = 0;
	http_access_log->en = TS_FALSE;
	http_access_log->domain[0] = 0x00;
	http_access_log->content[0] = 0x00;
	http_access_log->browser[0] = 0x00;
	http_access_log->request_type = '-';
	memset(http_access_log->src_ip, 0x00, 4);
	memset(http_access_log->dst_ip, 0x00, 4);
}

void init_http_access_log_list(void)
{	int i=0;
	for(i=0; i<MAX_DPI_LOG_LINES; i++)
   {	init_http_access_log(&http_access_logs[i]); }
}

static int ts_http_access_log_list_check_duplicate(IN http_access_log_t *http_access_log)
{
	int i=0;

	if(http_access_logs_current_position==-1) return TS_FALSE;
	
	for(i=0; i<MAX_DPI_LOG_LINES; i++)
   {
/*   	if(http_access_request_logs[i].en == TS_TRUE)
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
   */
   }
   
	return TS_FALSE;
} /* ts_http_access_log_list_check_duplicate */

static void ts_add_http_access_log_in_list(IN http_access_log_t *http_access_log)
{	if(http_access_log==NULL) return;
	if(ts_http_access_log_list_check_duplicate(http_access_log)==TS_TRUE) return;
	//increment current pointer (if list is still empty this pointer should point '-1' )
	if(http_access_logs_current_position<MAX_DPI_LOG_LINES) http_access_logs_current_position++; else http_access_logs_current_position=0;
	http_access_logs[http_access_logs_current_position].en = TS_TRUE;
	http_access_logs[http_access_logs_current_position].jiffies = jiffies;
	http_access_logs[http_access_logs_current_position].request_type = http_access_log->request_type;
	strcpy(http_access_logs[http_access_logs_current_position].domain, http_access_log->domain);
	strcpy(http_access_logs[http_access_logs_current_position].content, http_access_log->content);
	strcpy(http_access_logs[http_access_logs_current_position].browser, http_access_log->browser);
	memcpy(http_access_logs[http_access_logs_current_position].src_ip, http_access_log->src_ip, 4);
	memcpy(http_access_logs[http_access_logs_current_position].dst_ip, http_access_log->dst_ip, 4);
}

static int ts_parse_dpi_http_access(IN BYTE *buff, IN size_t bufflen, OUT http_access_log_t *http_access_log)
{
	BYTE *domain = http_access_log->domain;
	BYTE *content = http_access_log->content;

	//not a GET or POST packet since its lenght is < 20 bytes
	if(bufflen<20) { return TS_FALSE; }

	//Check if it is a valid GET or POST packet ?
	if( (buff[0]=='G' && buff[1]=='E' && buff[2]=='T') ) { http_access_log->request_type = 'G'; } //GET
	else if( (buff[0]=='P' && buff[1]=='O' && buff[2]=='S' && buff[3]=='T') ) {  http_access_log->request_type = 'P'; } //POST
	else { return TS_FALSE; } //neither GET or POST !!
	
	//point the start and end pos of the GET/POST
	unsigned char *get_start=NULL;
	if(http_access_log->request_type=='G') get_start = (unsigned char *)ts_memmem((BYTE *)buff, bufflen, (unsigned char *)"GET ", strlen("GET ")); 
	else if(http_access_log->request_type=='P') get_start = (unsigned char *)ts_memmem((BYTE *)buff, bufflen, (unsigned char *)"POST ", strlen("POST ")); 
	else return TS_FALSE;
	
	if(get_start==NULL) { return TS_FALSE; }

	unsigned char *get_end=NULL;
   get_end = ts_memmem((unsigned char *)get_start, (size_t)(bufflen-(size_t)(get_start-buff)), (unsigned char *)"\r\n", strlen("\r\n")); 
	if(get_end==NULL) { return TS_FALSE; }

	//Increment get_start and ignore "GET " or "POST "
	if(http_access_log->request_type=='G') get_start += strlen("GET ");
	else if(http_access_log->request_type=='P') get_start += strlen("POST ");
	else return TS_FALSE;


	//Check length of the content is out of standards (i.e. 98)
	if( (get_end-get_start) > 98 ) {  return TS_FALSE; }
	int k = 0;
	
	//Looks like we got a valid domain, so capture and save the same
	memcpy(content, get_start, (get_end-get_start));
	*(content+(get_end-get_start)) = '\0';
	
	//GET/POST /about.html HTTP.1.1 ... bla bla bla \r\n
	for(k=0;k<strlen(content);k++)
	{
		if(content[k]==' ') { content[k]='\0'; break; }
		if(content[k]==',') { content[k]=';'; } //we use ',' as
		if(k==49) { content[k]='\0'; break; } //chop the content if it is > 50 characters to 50 characters !!
	}

	//Check printable ASCII range ?	
	if(ts_found_printable_ascii( content, strlen(content), IS_NON_DOMAIN)== TS_FALSE) { return TS_FALSE; }
	
	int domain_len = 0;
	if(dpi_parse_buffer(buff, bufflen, "\nHost: ", "\r\n", domain, &domain_len)==TS_FALSE) { return TS_FALSE; }
	
	return TS_TRUE;
} /* ts_parse_dpi_http_access */

int ts_parse_dpi_http_access_pkt(IN struct sk_buff *skb)
{	int ip_hdr_len = ip_hdrlen(skb);
	int tcp_hdr_len = ts_get_tcp_hdr_size(skb);
		
	//Check it is a real DNS or some bogus or unknown packet ?
	/// If so do not process it further !!
	if( (skb->len-ip_hdr_len-tcp_hdr_len)<18) return TS_TRUE; //send true since this is http packet
	BYTE *pkt_buff = (skb->data+ip_hdr_len+tcp_hdr_len);
	size_t pkt_buff_len = (skb->len-ip_hdr_len-tcp_hdr_len);

	http_access_log_t http_access_log;
	init_http_access_log(&http_access_log);
	if(ts_parse_dpi_http_access(pkt_buff, pkt_buff_len, &http_access_log)==TS_TRUE)
   {	memcpy(http_access_log.src_ip, ts_get_ip_source_ip_addr(skb), 4);
   	memcpy(http_access_log.dst_ip, ts_get_ip_dest_ip_addr(skb), 4);
   	//Add or write to the global
   	spin_lock(&v_c_ts_http_access_log_list_lock_v_c);
   	ts_add_http_access_log_in_list(&http_access_log);
   	spin_unlock(&v_c_ts_http_access_log_list_lock_v_c);
   	return TS_TRUE;
   }
	return TS_FALSE;
}