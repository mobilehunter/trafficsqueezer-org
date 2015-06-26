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
#include <net/trafficsqueezer/dpi_pop.h>
pop_log_t *pop_logs; EXPORT_SYMBOL(pop_logs);
int pop_logs_current_position = -1; EXPORT_SYMBOL(pop_logs_current_position); //rotating log position in the array
int GROV_ts_dpi_pop_en = TS_TRUE; EXPORT_SYMBOL(GROV_ts_dpi_pop_en);
static void ts_init_pop_log(pop_log_t *pop_log)
{
	if(pop_log==NULL) return;
	pop_log->jiffies = 0;
	pop_log->en = TS_FALSE;
	pop_log->from[0] = 0x00;
   pop_log->to[0] = 0x00;
   pop_log->cc[0] = 0x00;
   pop_log->bcc[0]  = 0x00;
   pop_log->date[0]  = 0x00;
   pop_log->subject[0]  = 0x00;
	memset(pop_log->src_ip, 0x00, 4);
	memset(pop_log->dst_ip, 0x00, 4);
}

void ts_init_pop_log_list(void)
{	int i=0;
	for(i=0; i<MAX_DPI_LOG_LINES; i++)
   {	ts_init_pop_log(&pop_logs[i]); }
}

static int ts_pop_log_list_check_duplicate(IN pop_log_t *pop_log)
{
	int i=0;

	if(pop_logs_current_position==-1) return TS_FALSE;
	
	for(i=0; i<MAX_DPI_LOG_LINES; i++)
   {
/*   	if(dns_request_logs[i].en == TS_TRUE)
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
}

static void ts_add_pop_log_in_list(IN pop_log_t *pop_log)
{	if(pop_log==NULL) return;
	if(ts_pop_log_list_check_duplicate(pop_log)==TS_TRUE) return;
	//increment current pointer (if list is still empty this pointer should point '-1' )
	if(pop_logs_current_position<MAX_DPI_LOG_LINES) pop_logs_current_position++; else pop_logs_current_position=0;
	pop_logs[pop_logs_current_position].en = TS_TRUE;
	pop_logs[pop_logs_current_position].jiffies = jiffies;

	strcpy(pop_logs[pop_logs_current_position].from, pop_log->from);
	strcpy(pop_logs[pop_logs_current_position].to, pop_log->to);
	strcpy(pop_logs[pop_logs_current_position].cc, pop_log->cc);
	strcpy(pop_logs[pop_logs_current_position].bcc, pop_log->bcc);
	strcpy(pop_logs[pop_logs_current_position].subject, pop_log->subject);
	memcpy(pop_logs[pop_logs_current_position].src_ip, pop_log->src_ip, 4);
	memcpy(pop_logs[pop_logs_current_position].dst_ip, pop_log->dst_ip, 4);
}

static int ts_parse_dpi_pop(IN BYTE *buff, IN size_t bufflen, OUT pop_log_t *pop_log)
{
	int dns_request = 0; //0= GET, 1=POST
	BYTE *from = pop_log->from;  //get the parsed domain and store here.
	BYTE *to = pop_log->to;  //get the parsed domain and store here.
	BYTE *cc = pop_log->cc;  //get the parsed domain and store here.
	BYTE *bcc = pop_log->bcc;  //get the parsed domain and store here.
	BYTE *subject = pop_log->subject;  //get the parsed domain and store here.

	int ret_from = TS_FALSE;
	int ret_to = TS_FALSE;
	int ret_cc = TS_FALSE;
	int ret_bcc = TS_FALSE;

	size_t out_bufflen = 0;	
	
	ret_from = dpi_parse_buffer(buff, bufflen, "\nFrom: ", "\r\n", from, &out_bufflen);
	
	if(ret_from==TS_TRUE)
	{
		ret_to = dpi_parse_buffer(buff, bufflen, "\nTo: ", "\r\n", to, &out_bufflen);
		ret_cc = dpi_parse_buffer(buff, bufflen, "\nCc: ", "\r\n", cc, &out_bufflen);
		ret_bcc = dpi_parse_buffer(buff, bufflen, "\nBcc: ", "\r\n", bcc, &out_bufflen);
		
		//dpi_parse_buffer(buff, bufflen, "Received: ", "\r\n", out_buff, out_bufflen);
		//dpi_parse_buffer(buff, bufflen, "Date: ", "\r\n", out_buff, out_bufflen);
		//dpi_parse_buffer(buff, bufflen, "Message-ID: ", "\r\n", out_buff, out_bufflen);
		dpi_parse_buffer(buff, bufflen, "\nSubject: ", "\r\n", subject, &out_bufflen);
	}
	else
	{
		return TS_FALSE;
	}
	
	
	if(ret_to==TS_FALSE && ret_cc==TS_FALSE && ret_bcc==TS_FALSE)
	{
		return TS_FALSE;
	}
	

	return TS_TRUE;
} /* ts_parse_dpi_pop */

int ts_parse_dpi_pop_pkt(IN struct sk_buff *skb)
{	int ip_hdr_len = ip_hdrlen(skb);
	int tcp_hdr_len = ts_get_tcp_hdr_size(skb);
			
	//Check it is a real DNS or some bogus or unknown packet ?
	/// If so do not process it further !!
	if( (skb->len-ip_hdr_len-tcp_hdr_len)<18) return TS_TRUE; //send true, since this is pop packet !
			
	BYTE *pkt_buff = (skb->data+ip_hdr_len+tcp_hdr_len);
	size_t pkt_buff_len = (skb->len-ip_hdr_len-tcp_hdr_len);

	pop_log_t pop_log;
	ts_init_pop_log(&pop_log);
	if(ts_parse_dpi_pop(pkt_buff, pkt_buff_len, &pop_log)==TS_TRUE)
   {	memcpy(pop_log.src_ip, ts_get_ip_source_ip_addr(skb), 4);
   	memcpy(pop_log.dst_ip, ts_get_ip_dest_ip_addr(skb), 4);
   	//Add or write to the global
   	spin_lock(&v_c_ts_pop_log_list_lock_v_c);
   	ts_add_pop_log_in_list(&pop_log);
   	spin_unlock(&v_c_ts_pop_log_list_lock_v_c);
   	return TS_TRUE;
   }
	return TS_FALSE;
}