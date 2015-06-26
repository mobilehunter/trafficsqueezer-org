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
#include <linux/types.h>
#include <linux/in.h>
#include <linux/ctype.h>
#include <linux/gfp.h>
#include <net/trafficsqueezer/core.h>
#include <net/trafficsqueezer/stats.h>
#include <net/trafficsqueezer/skbuff.h>
#include <net/trafficsqueezer/coal.h>
#include <net/trafficsqueezer/coal_core.h>

int GROV_ts_coal_en = TS_FALSE; EXPORT_SYMBOL(GROV_ts_coal_en);
int G_ts_coal_proto_dns_en = TS_TRUE; EXPORT_SYMBOL(G_ts_coal_proto_dns_en);
#define TS_DEFAULT_BUCKET_TIMER_DELAY	300 //Milli-seconds
int GROV_ts_coal_bucket_timer_delay = TS_DEFAULT_BUCKET_TIMER_DELAY; EXPORT_SYMBOL(GROV_ts_coal_bucket_timer_delay);
#define BUCKET_DEFAULT_MTU_SIZE	1460  /* 1460 + some additional TS header bytes */
int GROV_ts_coal_bucket_size = BUCKET_DEFAULT_MTU_SIZE; EXPORT_SYMBOL(GROV_ts_coal_bucket_size);

ts_skb_coal_bucket_t ts_coal_ip_output_bkt; EXPORT_SYMBOL(ts_coal_ip_output_bkt);
ts_skb_coal_bucket_t ts_coal_ip_br_forward_bkt; EXPORT_SYMBOL(ts_coal_ip_br_forward_bkt);
struct timer_list ts_coal_ip_output_bkt_timer; EXPORT_SYMBOL(ts_coal_ip_output_bkt_timer);
struct timer_list ts_coal_ip_br_forward_bkt_timer; EXPORT_SYMBOL(ts_coal_ip_br_forward_bkt_timer);

static DEFINE_SPINLOCK(ts_send_coal_ip_output_bucket_lock);
static DEFINE_SPINLOCK(ts_send_coal_ip_br_forward_bucket_lock);

static int ts_coal_spin_lock(int flow);
static int ts_coal_spin_unlock(int flow);

static int ts_send_stored_pkt(int flow);
static int ts_is_contains_stored_packet(int flow);

static int ts_init_bucket(ts_skb_coal_bucket_t *coal_bkt);
static ts_skb_coal_bucket_t * ts_select_bucket(int flow);
static int ts_coalesce_skb_and_coal_bkt(struct sk_buff *skb, ts_skb_coal_bucket_t *coal_bkt, int flow);
static int ts_add_pkt_bucket(struct sk_buff *skb, int flow);
static int ts_uncoalesce_pkt_bucket(struct sk_buff *skb, struct sk_buff *skb2, int flow);

static int ts_start_bucket_timer(int flow);
static void ts_ip_output_bkt_timer_handler(unsigned long in_ts);
static void ts_ip_forward_bkt_timer_handler(unsigned long in_ts);
static void ts_br_forward_bkt_timer_handler(unsigned long in_ts);
static int ts_bucket_timer_delete(int flow);
static int ts_deliver_packet(IN struct sk_buff *skb, IN int flow);

int ts_coal_spin_lock(int flow)
{
	if(flow==TS_IP_OUTPUT)
		spin_lock(&ts_send_coal_ip_output_bucket_lock);
	else if(flow==TS_IP_FORWD || flow==TS_BR_FORWD)
		spin_lock(&ts_send_coal_ip_br_forward_bucket_lock);
		
	return TS_TRUE;
} /* ts_coal_spin_lock */

int ts_coal_spin_unlock(int flow)
{
	if(flow==TS_IP_OUTPUT)
		spin_unlock(&ts_send_coal_ip_output_bucket_lock);
	else if(flow==TS_IP_FORWD || flow==TS_BR_FORWD)
		spin_unlock(&ts_send_coal_ip_br_forward_bucket_lock);
		
	return TS_TRUE;
} /* ts_coal_spin_unlock */

int ts_store_or_send(IN struct sk_buff *skb, int flow)
{
	int ret;
	
	printk("@ ts_store_or_send\n");  
///////////Store or send if possible !

	/// send or store this packet. (DROP means it is added in stored packet)
	ts_coal_spin_lock(flow);
	ret = ts_add_pkt_bucket(skb, flow);
	ts_coal_spin_unlock(flow);
	
	return ret; 
	
} /* ts_store_or_send */


int ts_uncoal_or_send(IN struct sk_buff *skb, OUT struct sk_buff *skb2, int flow)
{
	int ret;
	
	printk("@ ts_uncoal_or_send\n");  

	/// uncoalesce or this packet. (DROP means it is dropped)
	ts_coal_spin_lock(flow);
	ret = ts_uncoalesce_pkt_bucket(skb, skb2, flow);
	ts_coal_spin_unlock(flow);
	
	return ret; 
} /* ts_uncoal_or_send */

int ts_uncoalesce_pkt_bucket(struct sk_buff *skb, struct sk_buff *skb2, int flow)
{
	BYTEx2 skb2_len=0x0000;
	skb2=NULL;
	printk("@ts_uncoalesce_pkt_bucket \n");
	
	if(ts_get_ts_coal_pkt_len(skb, &skb2_len)==TS_FALSE) return TS_FALSE; //not coalesced, send it as it is !
	if( (skb2_len > skb->len) || (skb2_len==0) ) { return TS_FALSE; } //this is impossible (coalesced packet is len > entire packet), seems it is not coalesced packet, send it as it is !
 
///////////Uncoalesce or send as it is !
	// we know now it is a TS coalesced packet.
	skb2 = pskb_copy(skb, GFP_ATOMIC);
	if(skb2==NULL) 
	{
		kfree_skb(skb);
		return TS_DROP; //Drop the current packet too, looks like some errors and inconsistency !
	} 

	printk("skb2 coalescing extracted !\n");
	ts_update_coal_wan_stats(FLOW_OUT); //skb2

	//now copy the contents back in the second packet.
	memcpy(skb2->data, (skb->data+(skb->len-skb2_len-6)), skb2_len);
	
	if(ts_skb_safe_trim(skb2, skb2_len))
	{
		ts_update_ip_tot_len(skb2);
		
		//Do not compute Transport layer checksum !
		/// hence just compute only IP checksum
		ts_ip_send_check(skb2);
	
		//Call respective API to send that packet.
		/// it is not required to send here, since it can be sent via main calling API.
	}
	else 
	{
		printk("ts_skb_safe_trim(skb2 ... error !\n");
		kfree_skb(skb2); skb2 = NULL;
		kfree_skb(skb);
		return TS_DROP; //Drop the current packet too, looks like some errors and inconsistency !
	}
	
	//Now treat the second packet.
	if(!ts_skb_safe_trim(skb, skb->len-skb2_len-6))
	{
		kfree_skb(skb);
		return TS_DROP;
	}
	
	return TS_TRUE; 
	
} /* ts_uncoalesce_pkt_bucket */

int ts_send_stored_pkt(flow)
{
	printk("@ ts_send_stored_pkt()\n");
	ts_skb_coal_bucket_t *coal_bkt = ts_select_bucket(flow);

	if(coal_bkt==NULL) return TS_FALSE;
	
	if(ts_is_contains_stored_packet(flow)==TS_TRUE)
	{
		//Call respective API to send that packet.
		ts_deliver_packet(coal_bkt->stored_skb, flow);

		//Now clean/init the bucket again
		ts_clean_bucket(coal_bkt);
			
		return TS_TRUE;
	}
	
	//Now clean/init the bucket again
	ts_clean_bucket(coal_bkt);
	
	return TS_FALSE;
} /* ts_send_stored_pkt */


int ts_is_contains_stored_packet(int flow)
{
	ts_skb_coal_bucket_t *coal_bkt = ts_select_bucket(flow);
	if(coal_bkt==NULL) return TS_FALSE;
	if(coal_bkt->enabled==TS_TRUE && coal_bkt->stored_skb!=NULL)  return TS_TRUE;
	return TS_FALSE;
} /* ts_is_contains_stored_packet */

/* Init Bucket data-structure */
int ts_init_bucket(ts_skb_coal_bucket_t *coal_bkt)
{
	if(coal_bkt==NULL) return TS_FALSE;
	coal_bkt->enabled = TS_FALSE;
	coal_bkt->pkt_remote_subnet_ip_list_id = -1;
	coal_bkt->pkt_remote_machine_ip_list_id = -1;
	coal_bkt->stored_skb = NULL;
	return TS_TRUE;
} /* ts_init_bucket */

int ts_clean_bucket(ts_skb_coal_bucket_t *coal_bkt)
{
	if(coal_bkt==NULL) return TS_FALSE;
	return ts_init_bucket(coal_bkt);
} /* ts_clean_bucket */

ts_skb_coal_bucket_t * ts_select_bucket(int flow)
{
	if(flow==TS_IP_OUTPUT)
		return &ts_coal_ip_output_bkt;
	else if(flow==TS_IP_FORWD || flow==TS_BR_FORWD)
		return &ts_coal_ip_br_forward_bkt;
		
	return NULL;
} /* ts_select_bucket */


int ts_coalesce_skb_and_coal_bkt(struct sk_buff *skb, ts_skb_coal_bucket_t *coal_bkt, int flow)
{
	size_t skb_len = skb->len;
	if(ts_skb_safe_put(skb, coal_bkt->stored_skb->len+2))
	{
		memcpy((skb->data+skb_len), coal_bkt->stored_skb->data, coal_bkt->stored_skb->len);
					
		//Set now the last 2 bytes
		*((BYTEx2 *)(skb->data+skb->len-2)) = (BYTEx2 ) htons(coal_bkt->stored_skb->len);
				
		kfree_skb(coal_bkt->stored_skb);
		ts_clean_bucket(coal_bkt);
		return TS_TRUE;
	}
	return TS_FALSE;
} /* ts_coalesce_skb_and_coal_bkt */


int ts_add_pkt_bucket(struct sk_buff *skb, int flow)
{
	ts_skb_coal_bucket_t *coal_bkt = ts_select_bucket(flow);
	int pkt_remote_subnet_ip_list_id = chk_pkt_remote_subnet_ip_list_id(ts_get_ip_dest_ip_addr(skb));
	int pkt_remote_machine_ip_list_id = chk_pkt_remote_machine_ip_list_id(ts_get_ip_dest_ip_addr(skb));
	ts_bucket_timer_delete(flow); //Delete the timer, to stop the same !!
	printk("@ 	ts_add_pkt_bucket\n");
	
	if(coal_bkt==NULL) return TS_FALSE; //bucket selection error, hence unable to add the packet !

	//Already near MTU value ?
	if(skb->len >=GROV_ts_coal_bucket_size){ ts_send_stored_pkt(flow); return TS_FALSE; }

	//Dont know where this packet is destined ?
	/// Or not a match w.r.t remote WAN network and machine ? !!
	// If remote-subnet is -1, then atleast remote-machine should be != -1  !!  (means both are -1, then dont allow this packet !)
	if(pkt_remote_subnet_ip_list_id==-1 && pkt_remote_machine_ip_list_id==-1){ ts_send_stored_pkt(flow); return TS_FALSE; }

	//Don't coalesce any DNS packets.
	if(skb->ts_ipproto==IPPROTO_UDP)
	{
		if(skb->ts_proto_port==PROTO_DNS)
		{
			//Do not coalesce protocol dns ?
			if(G_ts_coal_proto_dns_en==TS_FALSE)
			{
				ts_send_stored_pkt(flow);
				return TS_FALSE;
			}
		}
	}

	//Already contains packet ?
	if(ts_is_contains_stored_packet(flow)==TS_TRUE)
	{
		printk("Bkt Already contains packet\n");
	
		if( (skb->len+coal_bkt->stored_skb->len)<GROV_ts_coal_bucket_size) 	//if coalesceable,  then coalesce and send ?
		{
			//If both are meant to same remote machine and it is enabled ?
			if((pkt_remote_machine_ip_list_id==coal_bkt->pkt_remote_machine_ip_list_id) && (pkt_remote_machine_ip_list_id!=-1 && coal_bkt->pkt_remote_machine_ip_list_id!=-1))
			{
				//Coalesce and send this packet !
				if(ts_coalesce_skb_and_coal_bkt(skb,coal_bkt,flow)==TS_TRUE) { return TS_TRUE; }
				else //seems some packet skb_put error, so send uncoalesced two packets !
				{
					ts_send_stored_pkt(flow);
				}
			}
			else if(pkt_remote_machine_ip_list_id==100 && coal_bkt->pkt_remote_machine_ip_list_id==100) // remote-machine check is not enabled ? 
			{
				if(compare_pkts_dest_ip(ts_get_ip_dest_ip_addr(skb), ts_get_ip_dest_ip_addr(coal_bkt->stored_skb)))
				{
					//Coalesce and send this packet !
					if(ts_coalesce_skb_and_coal_bkt(skb,coal_bkt,flow)==TS_TRUE) { return TS_TRUE; }
					else //seems some packet skb_put error, so send uncoalesced two packets !
					{
						ts_send_stored_pkt(flow);
					}
				}
			}
			else if( pkt_remote_subnet_ip_list_id!=coal_bkt->pkt_remote_subnet_ip_list_id ) //If both are not destined to the same subnet series too ?
			{
				ts_send_stored_pkt(flow);
			}
			else //Same subnet !
			{
				//seems remote ip subnet checks are disabled !
				if(pkt_remote_subnet_ip_list_id==100 && coal_bkt->pkt_remote_subnet_ip_list_id==100) 
				{
					//Now check atleast both of them are destined to the same machine ?
					if(compare_pkts_dest_ip(ts_get_ip_dest_ip_addr(skb), ts_get_ip_dest_ip_addr(coal_bkt->stored_skb)))
					{
						printk("here - 6\n");
						//Coalesce and send this packet !
						if(ts_coalesce_skb_and_coal_bkt(skb,coal_bkt,flow)==TS_TRUE) { return TS_TRUE; }
						else //seems some packet skb_put error, so send uncoalesced two packets !
						{
							ts_send_stored_pkt(flow);
						}
					}
					else //remote ip subnet is disabled, and the packets are not also destined to same machine ?? ! 
					{
						ts_send_stored_pkt(flow);
					}
				}
				else if(pkt_remote_subnet_ip_list_id==-1 && coal_bkt->pkt_remote_subnet_ip_list_id==-1) //since we now enable either remote machine or remote subnet = -1, so check this condition too !
				{
					ts_send_stored_pkt(flow);
				} 
				else //remote ip subnet check is enabled, and there is a match of both packets destined to same remote wan !
				{
					//Coalesce and send this packet !
					if(ts_coalesce_skb_and_coal_bkt(skb,coal_bkt,flow)==TS_TRUE) { return TS_TRUE; }
					else //seems some packet skb_put error, so send uncoalesced two packets !
					{
						ts_send_stored_pkt(flow);
					}
				}
			}
		}
		else //all checks are ERROR, so send the stored packet.
		{
			ts_send_stored_pkt(flow);
		}
	}

/// Try adding this packet in a fresh clean bucket !
	
	printk("now try adding packet \n");
	ts_clean_bucket(coal_bkt); // to avoid any crash clean it once.

	printk("All clear, now add (store) this packet ! \n");
/// All clear, now add (store) this packet !
	coal_bkt->stored_skb = skb;
	coal_bkt->pkt_remote_subnet_ip_list_id = pkt_remote_subnet_ip_list_id;
	coal_bkt->pkt_remote_machine_ip_list_id = pkt_remote_machine_ip_list_id;
	coal_bkt->enabled = TS_TRUE;
	
	ts_start_bucket_timer(flow); //Start the timer now !

   return TS_DROP; //added this packet, hence go to drop cycle to ignore !
} /* ts_add_pkt_bucket */


int ts_start_bucket_timer(int flow)
{
	if(flow==TS_IP_OUTPUT)
	{
			ts_coal_ip_output_bkt_timer.data = (unsigned long) &ts_coal_ip_output_bkt;
    	   ts_coal_ip_output_bkt_timer.function = ts_ip_output_bkt_timer_handler;
    		//Delay to expire the timer - really depends on the network data delivery speeds
    		ts_coal_ip_output_bkt_timer.expires = jiffies+((int)GROV_ts_coal_bucket_timer_delay/4); //Delay in Milli-Seconds Approx (1 Jiffy = 4 ms)
    		add_timer(&ts_coal_ip_output_bkt_timer);
	}
	else if(flow==TS_IP_FORWD)
	{
			ts_coal_ip_br_forward_bkt_timer.data = (unsigned long) &ts_coal_ip_br_forward_bkt;
    	   ts_coal_ip_br_forward_bkt_timer.function = ts_ip_forward_bkt_timer_handler;
    		//Delay to expire the timer - really depends on the network data delivery speeds
    		ts_coal_ip_br_forward_bkt_timer.expires = jiffies+((int)GROV_ts_coal_bucket_timer_delay/4); //Delay in Milli-Seconds Approx (1 Jiffy = 4 ms)
    		add_timer(&ts_coal_ip_br_forward_bkt_timer);
	}
	else if(flow==TS_BR_FORWD)
	{
			ts_coal_ip_br_forward_bkt_timer.data = (unsigned long) &ts_coal_ip_br_forward_bkt;
    	   ts_coal_ip_br_forward_bkt_timer.function = ts_br_forward_bkt_timer_handler;
    		//Delay to expire the timer - really depends on the network data delivery speeds
    		ts_coal_ip_br_forward_bkt_timer.expires = jiffies+((int)GROV_ts_coal_bucket_timer_delay/4); //Delay in Milli-Seconds Approx (1 Jiffy = 4 ms)
    		add_timer(&ts_coal_ip_br_forward_bkt_timer);
	}

    return TS_TRUE;
} /* ts_start_bucket_timer */

void ts_ip_output_bkt_timer_handler(unsigned long in_ts)
{
	printk("@ ts_ip_output_bkt_timer_handler()\n");
	ts_coal_spin_lock(TS_IP_OUTPUT);
	ts_send_stored_pkt(TS_IP_OUTPUT);
	ts_coal_spin_unlock(TS_IP_OUTPUT);
}

void ts_ip_forward_bkt_timer_handler(unsigned long in_ts)
{
	printk("@ ts_ip_forward_bkt_timer_handler()\n");
	ts_coal_spin_lock(TS_IP_BR_FORWD);
	ts_send_stored_pkt(TS_IP_FORWD);
	ts_coal_spin_unlock(TS_IP_BR_FORWD);
}

void ts_br_forward_bkt_timer_handler(unsigned long in_ts)
{
	printk("@ ts_br_forward_bkt_timer_handler()\n");
	ts_coal_spin_lock(TS_IP_BR_FORWD);
	ts_send_stored_pkt(TS_BR_FORWD);
	ts_coal_spin_unlock(TS_IP_BR_FORWD);
}

int ts_bucket_timer_delete(int flow)
{
   if(flow==TS_IP_OUTPUT)
	{
		del_timer(&ts_coal_ip_output_bkt_timer);
	}
	else if(flow==TS_IP_FORWD || flow==TS_BR_FORWD)
	{	
		del_timer(&ts_coal_ip_br_forward_bkt_timer);
	}
	return TS_TRUE;
} /* ts_bucket_timer_delete */

int ts_deliver_packet(IN struct sk_buff *skb, IN int flow)
{
	printk("@ ts_deliver_packet()\n");
	
	if(skb==NULL) return TS_FALSE;
	
	if(flow==TS_IP_OUTPUT)
	{
		/****** disabling for dev_queue_xmit ts_ip_output_deliver_coalesce_packet(skb); */
	}
	else if(flow==TS_IP_FORWD)
	{	
		/********** ts_ip_forward_deliver_coalesce_packet(skb); */
	}
	else if(flow==TS_BR_FORWD)
	{	
		
	}
	
	return TS_TRUE;
} /* ts_deliver_packet */
