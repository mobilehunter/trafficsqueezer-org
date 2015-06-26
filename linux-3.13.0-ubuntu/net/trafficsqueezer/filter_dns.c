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
#include <net/sock.h>
#include <linux/ctype.h>
#include <net/trafficsqueezer/core.h>
#include <net/trafficsqueezer/memreplace.h>
#include <net/trafficsqueezer/stats.h>
#include <net/trafficsqueezer/filter_dns.h>

dns_domain_t *dns_domains; EXPORT_SYMBOL(dns_domains);
int G_ts_filter_dns_en = TS_FALSE; EXPORT_SYMBOL(G_ts_filter_dns_en);

void add_ts_dns_domain_in_list(char *domain_string)
{	int i=0;
	for(i=0;i<MAX_DNS_DOMAINS;i++)
	{
		if(dns_domains[i].en==TS_FALSE)
		{  add_ts_dns_domain(&dns_domains[i], domain_string); break; }
	}
}

void del_ts_dns_domain_in_list(char *domain_string)
{	int i=0;
	for(i=0;i<MAX_DNS_DOMAINS;i++)
	{
		if(dns_domains[i].en==TS_TRUE)
		{
			if(!strcmp(dns_domains[i].string_domain, domain_string)) 
			{
				dns_domains[i].binary_domain_len = 0;
				dns_domains[i].en=TS_FALSE;
				break;
			}
		}
	}
}

int add_ts_dns_domain(dns_domain_t *dns_domain, char *domain_string)
{	BYTE res_len = 0;
	char *temp = domain_string;
	char res[100];

	strcpy(dns_domain->string_domain, domain_string);
	dns_domain->en = TS_TRUE;
	dns_domain->binary_domain_len = 0;

	int i = 0;
	int dot_count = 0;
	//Check if the buffer is terminating 
	while( *temp!='\0' && *temp!='\n' )
	{
		// "." is the delimiter 
		if( (*temp)!='.' )
		{	
			//if "." is not found , copy the characters to result buf 
			res[i] = *temp;
			i++;
			res[i] = '\0';
		}
		else
		{
			res_len = strlen(res);
			dns_domain->binary_domain[dns_domain->binary_domain_len] = res_len;
			dns_domain->binary_domain_len++;
			memcpy( (dns_domain->binary_domain+dns_domain->binary_domain_len), res, res_len );
			dns_domain->binary_domain_len+=res_len;
			dot_count++;
			i = 0;
			res[0]='\0';
		}
		temp++;
    	}	

	if(dot_count==0) //Seems a partial domain name with no "." inbetween example: "abc" !
	{
		strcpy(dns_domain->binary_domain, dns_domain->string_domain);
		dns_domain->binary_domain_len = strlen(dns_domain->string_domain);
	}
	else 
	{	
		res_len = strlen(res);
		//Full domain or partial domain ? (a partial domain always ends with '.' )
		if(res_len!=0)
		{
			dns_domain->binary_domain[dns_domain->binary_domain_len] = res_len;
			dns_domain->binary_domain_len++;
			memcpy( (dns_domain->binary_domain+dns_domain->binary_domain_len), res, res_len );
			dns_domain->binary_domain_len+=res_len;
			//Add \0 into the length to do a correct 1:1 domain URL compare !
			dns_domain->binary_domain[dns_domain->binary_domain_len] = '\0';
			dns_domain->binary_domain_len++;
		}
		else  //Partial DNS example: "abc.co."
		{
			//Do nothing, since it is a partial domain !
		}
	}

	{
		printk("block-domain:");
		for(i=0;i<dns_domain->binary_domain_len;i++)
		{
			printk("%02x:", dns_domain->binary_domain[i]);
		}
		printk("\n");
	}		
	return TS_TRUE;
}


//IMPORTANT: Call this API strictly only after ts_skb_can_be_processed()
int ts_filter_dns(struct sk_buff *skb)
{
	if(!G_ts_filter_dns_en) return TS_TRUE;
	
	if(skb->ts_ipproto==IPPROTO_UDP)
	{
		if(skb->ts_proto_port==PROTO_DNS)
		{
			//Check it is a real DNS or some bogus or unknown packet ?
			/// If so do not process it further !!
			
			/************ commented temporarily for ip-payload optimization
			if( (skb->len-skb->ts_ip_hdr_size-skb->ts_trns_hdr_size)<18) return TS_TRUE;
			
			BYTE *pkt_buff = (skb->data+(skb->ts_ip_hdr_size+skb->ts_trns_hdr_size+10));
			size_t pkt_buff_len = (skb->len-(skb->ts_ip_hdr_size-skb->ts_trns_hdr_size-10));

			int i=0;
			for(i=0;i<MAX_DNS_DOMAINS;i++)
			{
				if(dns_domains[i].en==TS_TRUE)
				{
					if(ts_memmem( (BYTE *)pkt_buff, pkt_buff_len, (BYTE *)dns_domains[i].binary_domain, (size_t)dns_domains[i].binary_domain_len)!=NULL)
     				{
     					if(ts_pkt_to_wan(skb))
     					{ ts_filter_dns_stats.lan_filter_dns_pkts++; ts_filter_dns_stats.lan_filter_dns_bytes_saved+=skb->len; }
						else if(ts_pkt_to_lan(skb))
						{ ts_filter_dns_stats.wan_filter_dns_pkts++; ts_filter_dns_stats.wan_filter_dns_bytes_saved+=skb->len; }
	
     					kfree_skb(skb);
						//printk("Blocking this DNS request (%s) !\n", dns_domains[i].string_domain);
						return TS_DROP;
     				}
				}	
			}
			************/
		}
	}
	return TS_TRUE;	
}