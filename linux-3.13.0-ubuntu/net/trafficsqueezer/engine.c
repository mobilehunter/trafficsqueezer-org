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
#include <net/checksum.h>
#include <linux/route.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/ctype.h>
#include <linux/gfp.h>
#include <net/trafficsqueezer/core.h>
#include <net/trafficsqueezer/skbuff.h>
#include <net/trafficsqueezer/comp.h>
#include <net/trafficsqueezer/templ.h>
#include <net/trafficsqueezer/coal.h>
#include <net/trafficsqueezer/engine.h>
#include <net/trafficsqueezer/coal_core.h>

optmem_t optmem[MAX_PKTMEM_LIST];
unoptmem_t unoptmem[MAX_PKTMEM_LIST];

static int get_optmem_pos(void)
{	int i=0;
	spin_lock(&optmem_lock);
	for(i=0;i<MAX_PKTMEM_LIST;i++)
	{	
		if(!optmem[i].en) 
		{ optmem[i].en=true;
		  optmem[i].flag=optmem[i].flag2=0x00;
		  optmem[i].templ_id=0x00;
		  optmem[i].buflen=optmem[i].buf2len=0;
		  spin_unlock(&optmem_lock);
		  return i;
		}
	}
	spin_unlock(&optmem_lock);
	return -1;
}

static void free_optmem(int i) { spin_lock(&optmem_lock); optmem[i].en=false; spin_unlock(&optmem_lock); }

static int get_unoptmem_pos(void)
{	int i=0;
	spin_lock(&unoptmem_lock);
	for(i=0;i<MAX_PKTMEM_LIST;i++)
	{	
		if(!unoptmem[i].en) 
		{ unoptmem[i].en=true;
		  unoptmem[i].flag=0x00;
		  unoptmem[i].templ_id=0x00;
		  unoptmem[i].buflen=0;
		  spin_unlock(&unoptmem_lock);
		  return i;
		}
	}
	spin_unlock(&unoptmem_lock);
	return -1;
}

static void free_unoptmem(int i) { spin_lock(&unoptmem_lock); unoptmem[i].en=false; spin_unlock(&unoptmem_lock); }

static void finish_pkt(struct sk_buff *skb, bool tspkt)
{	
	if(tspkt==true)
   { if(skb->ts_ip_hdr->protocol==IPPROTO_ICMP) { skb->ts_ip_hdr->protocol=skb->ts_ipproto=IPPROTO_TS_ICMP; }
     else if(skb->ts_ip_hdr->protocol==IPPROTO_TCP) { skb->ts_ip_hdr->protocol=skb->ts_ipproto=IPPROTO_TS_TCP; }
     else if(skb->ts_ip_hdr->protocol==IPPROTO_UDP) { skb->ts_ip_hdr->protocol=skb->ts_ipproto=IPPROTO_TS_UDP; }
     else if(skb->ts_ip_hdr->protocol==IPPROTO_SCTP) { skb->ts_ip_hdr->protocol=skb->ts_ipproto=IPPROTO_TS_SCTP; }
   }
   else
   {  if(skb->ts_ip_hdr->protocol==IPPROTO_TS_ICMP) { skb->ts_ip_hdr->protocol=skb->ts_ipproto=IPPROTO_ICMP; }
      else if(skb->ts_ip_hdr->protocol==IPPROTO_TS_TCP) { skb->ts_ip_hdr->protocol=skb->ts_ipproto=IPPROTO_TCP; }
      else if(skb->ts_ip_hdr->protocol==IPPROTO_TS_UDP) { skb->ts_ip_hdr->protocol=skb->ts_ipproto=IPPROTO_UDP; }
      else if(skb->ts_ip_hdr->protocol==IPPROTO_TS_SCTP) { skb->ts_ip_hdr->protocol=skb->ts_ipproto=IPPROTO_SCTP; }
   }
	ip_send_check(skb->ts_ip_hdr);
}

void ts_opt(struct sk_buff *skb)
{	
	#ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
	printk("@ ts_opt() - pkt-dev: %s\n", skb->dev->name);
	#endif
	if(skb->ts_ip_pyld_size<TS_PKT_OPT_THRESHOLD) return;

	if(G_ts_r_ip_ntwrk_machine_en)
	{ 	if(!chk_pkt_remote_subnet_ip_list(ts_get_ip_dest_ip_addr(skb))) //if not remote-subnet check, then check for remote-machine possibly !
	   { if(!chk_pkt_remote_machine_ip_list(ts_get_ip_dest_ip_addr(skb))){ return; } }
	}

	int pos = get_optmem_pos(); if(pos==-1) { printk("ERROR: Getting get_optmem_pos()\n"); return; }
	
	int eat_srcproto=false;
	if(skb->ts_srcproto_port==PROTO_HTTP)
	{ optmem[pos].flag |= TS_FLAG_SRCPORT_HTTP;
	  optmem[pos].flag2|= TS_FLAG_SRCPORT_HTTP;
	  eat_srcproto=true;
	  #ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
	  printk("eating srcproto: HTTP\n");
	  #endif
	}
	else if(skb->ts_srcproto_port==PROTO_DNS) 
	{ optmem[pos].flag |= TS_FLAG_SRCPORT_DNS;
	  optmem[pos].flag2|= TS_FLAG_SRCPORT_DNS;
	  eat_srcproto=true;
	  #ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
	  printk("eating srcproto: DNS\n");
	  #endif
	}
	
	if(eat_srcproto==true)
	{
		optmem[pos].buflen=optmem[pos].buf2len=(size_t)(skb->ts_ip_pyld_size-2);
		memcpy((BYTE *)optmem[pos].buf, (BYTE *)(skb->ts_ip_pyld+2), (size_t)optmem[pos].buflen);
		memcpy((BYTE *)optmem[pos].buf2, (BYTE *)(skb->ts_ip_pyld+2), (size_t)optmem[pos].buf2len);
	}
	else
	{
		optmem[pos].buflen=optmem[pos].buf2len=(size_t)skb->ts_ip_pyld_size;
		memcpy((BYTE *)optmem[pos].buf, (BYTE *)skb->ts_ip_pyld, (size_t)optmem[pos].buflen);
		memcpy((BYTE *)optmem[pos].buf2, (BYTE *)skb->ts_ip_pyld, (size_t)optmem[pos].buf2len);
	}
	
	ts_http_templ(&(optmem[pos].flag), skb->ts_proto_port, optmem[pos].buf, &(optmem[pos].buflen), optmem[pos].wrkmem);
	ts_templ(&(optmem[pos].flag), &(optmem[pos].templ_id), skb->ts_proto_port, optmem[pos].buf, &(optmem[pos].buflen), optmem[pos].wrkmem);
	ts_common_templ(&(optmem[pos].flag), optmem[pos].buf, &(optmem[pos].buflen), optmem[pos].wrkmem);
	ts_generic_templ(&(optmem[pos].flag), optmem[pos].buf, &(optmem[pos].buflen), optmem[pos].wrkmem);
	if(optmem[pos].flag==0x00||optmem[pos].flag==TS_FLAG_SRCPORT_HTTP||optmem[pos].flag==TS_FLAG_SRCPORT_DNS) goto ts_opt_TEMPL_SKIP;
	ts_comp(&(optmem[pos].flag), optmem[pos].buf, &(optmem[pos].buflen), optmem[pos].wrkmem, optmem[pos].lz4hc_wrkmem);

ts_opt_TEMPL_SKIP:
	ts_comp(&(optmem[pos].flag2), optmem[pos].buf2, &(optmem[pos].buf2len), optmem[pos].wrkmem, optmem[pos].lz4hc_wrkmem);

	if(optmem[pos].buflen<optmem[pos].buf2len && optmem[pos].flag!=0x00)
	{  optmem[pos].buflen+=2;
		if(ts_skb_safe_trim(skb, (skb->ts_l2_hdr_size+skb->ts_ip_hdr_size+optmem[pos].buflen)))
		{	*((BYTE *)(optmem[pos].buf+(optmem[pos].buflen-1)))=optmem[pos].flag; //include flag
		   *((BYTE *)(optmem[pos].buf+(optmem[pos].buflen-2)))=optmem[pos].templ_id; //include templ_id
			#ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
			printk("Choosing Comp +/ Temp [buf(%d)] - buflen: %zu - templ_id: %d - flag: %d\n", pos, optmem[pos].buflen, optmem[pos].templ_id, optmem[pos].flag);
			#endif
			
			//!!! WARNING: Do before sync (and dont refer skb->ts_ip_hdr instead use ip_hdr(skb) since it is not yet set)
			ip_hdr(skb)->tot_len=htons(skb->ts_ip_hdr_size+optmem[pos].buflen);
			
			ts_parse_pkt(skb, "]]Int-SKB-Sync-Vars[[");
			memcpy((BYTE *)skb->ts_ip_pyld, (BYTE *)optmem[pos].buf, (size_t)optmem[pos].buflen);
			finish_pkt(skb, true);
		}
	}
	else if(optmem[pos].flag2!=0x00)
	{	optmem[pos].buf2len+=2;
		if(ts_skb_safe_trim(skb, (skb->ts_l2_hdr_size+skb->ts_ip_hdr_size+optmem[pos].buf2len)))
		{	*((BYTE *)(optmem[pos].buf2+(optmem[pos].buf2len-1)))=optmem[pos].flag2; //include last-byte flag
		   *((BYTE *)(optmem[pos].buf2+(optmem[pos].buf2len-2)))=optmem[pos].templ_id; //include templ_id (anyway it is 0x00)
			#ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
			printk("Choosing Comp alone [buf2(%d)] - buf2len: %zu - templ_id: %d - flag2: %d\n", pos, optmem[pos].buf2len, optmem[pos].templ_id, optmem[pos].flag2);
			#endif
			
			//!!! WARNING: Do before sync (and dont refer skb->ts_ip_hdr instead use ip_hdr(skb) since it is not yet set)
			ip_hdr(skb)->tot_len=htons(skb->ts_ip_hdr_size+optmem[pos].buf2len);
			
			ts_parse_pkt(skb, "]]Int-SKB-Sync-Vars[[");
			memcpy((BYTE *)skb->ts_ip_pyld, (BYTE *)optmem[pos].buf2, (size_t)optmem[pos].buf2len);
			finish_pkt(skb, true);
		}
	}
	
  free_optmem(pos);
}

int ts_unopt(struct sk_buff *skb)
{
	#ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
	printk("@ ts_unopt() - pkt-dev: %s\n", skb->dev->name);
	#endif
	
	if(!ts_is_ts_pkt(skb)) return TS_FALSE;
	
	int pos = get_unoptmem_pos(); if(pos==-1) { printk("ERROR: Getting get_unoptmem_pos()\n"); return TS_DROP; }

	unoptmem[pos].flag=(BYTE)(*(skb->ts_ip_pyld+skb->ts_ip_pyld_size-1));
	unoptmem[pos].templ_id=(BYTE)(*(skb->ts_ip_pyld+skb->ts_ip_pyld_size-2));
	#ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
	printk("[buf(%d)] Extracted: templ_id: %d - flag: %d\n", pos, unoptmem[pos].templ_id, unoptmem[pos].flag);
	#endif

	unoptmem[pos].buflen = (size_t)(skb->ts_ip_pyld_size-2); //exclude last 2-bytes (templ_id, flag)
	memcpy((BYTE *)unoptmem[pos].buf, (BYTE *)skb->ts_ip_pyld, (size_t)unoptmem[pos].buflen);

	bool error=false;
   if(ts_chk_pkt_tag(unoptmem[pos].flag, TS_FLAG_COMP)) { if(!ts_decomp(unoptmem[pos].buf, &(unoptmem[pos].buflen), unoptmem[pos].wrkmem)) {error=true; goto ts_unopt_ERROR;} }
   if(ts_chk_pkt_tag(unoptmem[pos].flag, TS_FLAG_TEMPL_GENERIC)) {if(!ts_generic_untempl(unoptmem[pos].buf, &(unoptmem[pos].buflen))) {error=true; goto ts_unopt_ERROR;} }
   if(ts_chk_pkt_tag(unoptmem[pos].flag, TS_FLAG_TEMPL_COMMON)) {if(!ts_common_untempl(unoptmem[pos].buf, &(unoptmem[pos].buflen))) {error=true; goto ts_unopt_ERROR;} }
   if(ts_chk_pkt_tag(unoptmem[pos].flag, TS_FLAG_TEMPL)) {if(!ts_untempl(unoptmem[pos].templ_id, unoptmem[pos].buf, &(unoptmem[pos].buflen))) {error=true; goto ts_unopt_ERROR;} }
   if(ts_chk_pkt_tag(unoptmem[pos].flag, TS_FLAG_HTTP)) {if(!ts_http_untempl(unoptmem[pos].buf, &(unoptmem[pos].buflen))) {error=true; goto ts_unopt_ERROR;} }

	size_t add_srcport_len=0;
	if(ts_chk_pkt_tag(unoptmem[pos].flag, TS_FLAG_SRCPORT_HTTP)||ts_chk_pkt_tag(unoptmem[pos].flag, TS_FLAG_SRCPORT_DNS)) { add_srcport_len=2;}

	if(ts_skb_safe_put(skb, (unoptmem[pos].buflen+add_srcport_len)-skb->ts_ip_pyld_size))
	{
		//!!! WARNING: Do before sync (and dont refer skb->ts_ip_hdr instead use ip_hdr(skb) since it is not yet set)
		ip_hdr(skb)->tot_len=htons(skb->ts_ip_hdr_size+(unoptmem[pos].buflen+add_srcport_len));
		
		ts_parse_pkt(skb, "]]Int-SKB-Sync-Vars[[");
		if(add_srcport_len==2)
		{
			if(ts_chk_pkt_tag(unoptmem[pos].flag, TS_FLAG_SRCPORT_HTTP)) 
			{ *((BYTE *)(skb->ts_ip_pyld+0))=(BYTE)0x00;
			  *((BYTE *)(skb->ts_ip_pyld+1))=(BYTE)0x50;
			  #ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
			  printk("adding srcport: HTTP\n");
			  #endif
			}
			else if(ts_chk_pkt_tag(unoptmem[pos].flag, TS_FLAG_SRCPORT_DNS))
			{ *((BYTE *)(skb->ts_ip_pyld+0))=(BYTE)0x00;
			  *((BYTE *)(skb->ts_ip_pyld+1))=(BYTE)0x35;
			  #ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
			  printk("adding srcport: DNS\n");
			  #endif
			}
		}
		memcpy((BYTE *)(skb->ts_ip_pyld+add_srcport_len), (BYTE *)unoptmem[pos].buf, (size_t)unoptmem[pos].buflen);
		
		finish_pkt(skb, false);
	}
	else { error=true; }

ts_unopt_ERROR:
	free_unoptmem(pos);
	if(error) { kfree_skb(skb); skb=NULL; printk("ts_unopt_ERROR: dropping pkt\n"); return TS_DROP; }

  return TS_TRUE;
}

int ts_opt_coalesce_flow_engine(struct sk_buff *skb, int flow)
{
   int ret = 0;
   BYTE flag=0x00;

	//printk("@ ts_opt_coalesce_flow_engine()\n");   
   
   ret = ts_store_or_send(skb, flow);
   
   if(ret==TS_DROP) //DROP = packet is added in stored bucket !
   {
   		return TS_DROP;
   }
   
   if(ret==TS_FALSE) //packet is un-touched, and hence send it as it is !
   {
   		return TS_TRUE;	
   }
   
   if(ret==TS_TRUE) // packet is now coalesced packet !
   {
   	#ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
   	printk("@ ts_opt_coalesce_flow_engine() -> packet is now coalesced packet !\n");
   	#endif
   	flag |= TS_FLAG_COAL;
   	ts_add_ts_coal_pkt_tag(skb, flag);
   	/************* disabled for now for ip-payload optimization stuff skb->tspkt=true;  **********/
   	ts_update_ip_tot_len(skb);
   		
		//Do not compute Transport layer checksum !
		/// hence just compute only IP checksum
		ts_ip_send_check(skb);
		return TS_TRUE;
   }
   
   return TS_TRUE;
}

int ts_unopt_coalesce_flow_engine(struct sk_buff *skb, struct sk_buff *skb2, int flow)
{
	BYTE flag=0x0000;
	
	int ret = 0;

	//printk("@ ts_unopt_coalesce_flow_engine()\n");

	if(ts_get_ts_coal_pkt_tag(skb, &flag)==TS_FALSE) { printk("@ ts_unopt_coalesce_flow_engine() - not coalesced packet\n"); return TS_TRUE; } //not coalesced !
	
	#ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
	printk("@ ts_unopt_coalesce_flow_engine()  - is a coalesced packet\n");
	#endif
	
	ret = ts_uncoal_or_send(skb, skb2, flow);
	
	if(ret==TS_DROP) //DROP 
   {
   		return TS_DROP;
   }
   
	if(ret==TS_FALSE) //packet is un-touched, and hence send it as it is !
   {
   		return TS_TRUE;	
   }
   
   if(ret==TS_TRUE) // packet is now un-coalesced packet !
   {
   	ts_update_ip_tot_len(skb);
		//Do not compute Transport layer checksum !
		/// hence just compute only IP checksum
		ts_ip_send_check(skb);
		return TS_TRUE;
   }
	
   return ret;
}
