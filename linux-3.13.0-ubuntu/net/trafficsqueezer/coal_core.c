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
#include <net/trafficsqueezer/skbuff.h>
#include <net/trafficsqueezer/coal_core.h>
int ts_skb_can_be_coal_processed(struct sk_buff *skb)
{
	if(!(ts_skb_dev_wan(skb) || ts_skb_dev_lan(skb))) return false;
	if(!ts_skb_make_writable(skb)) return TS_FALSE;

	return TS_TRUE;
} /* ts_skb_can_be_coal_processed */

int ts_add_ts_coal_pkt_tag(struct sk_buff *skb, BYTE flag)
{
	ts_skb_safe_put(skb, 1); //add 1 byte
	*(skb->data+skb->len-1)=flag;

	/* disabled for IP-Payload optimization changes ts_set_ip_tos(skb); */
	
   return TS_TRUE;
} /* ts_add_ts_coal_pkt_tag */

int ts_is_ts_coalesce_pkt(struct sk_buff *skb)
{
     //////////if(skb->ts_ethproto==TS_IPV4)
     {
	     if(skb->ts_ipproto==IPPROTO_TCP || skb->ts_ipproto==IPPROTO_UDP)
		{
			
			/* disabled for IP-Payload optimization changes if(!ts_check_ip_tos(skb)) return TS_FALSE; */

			if( (skb->len)>(ip_hdrlen(skb)+8+4) ) //aproximately atleast 
			{
				//Extract flag
				BYTE flag=(*(skb->data+skb->len-1));

				if(ts_chk_pkt_tag(flag, TS_FLAG_COAL)==TS_TRUE) return TS_TRUE;
	
			}
		}
     }
     return TS_FALSE;
} /* ts_is_ts_coalesce_pkt */

//Do not allow a TS coalesce packet into TCP/IP Stack !
int ts_ts_coal_pkt_safe_drop(struct sk_buff *skb, char *comment)
{
	if(comment==NULL) return TS_TRUE;
	if(skb==NULL) 
	{
		printk("Seems already coalesce packet is dropped [flow: %s]\n", comment);
		return TS_DROP; //already skb is null, hence ideally it means dropped ! (else may crash kernel in later stages assuming packet is there !)
	}
	
	if(ts_is_ts_coalesce_pkt(skb)==TS_TRUE) //Seems it is still a TS packet  
	{
		kfree_skb(skb);
		printk("Cowardly safe dropping a TS coalesce packet [flow: %s]\n", comment);
		return TS_DROP;
	}
	
	//It is sure now it is not a TS packet, hence RESET IP->TOS bit if set ! 
	//ts_reset_ip_tos(skb);
	
	return TS_TRUE;
} /* ts_ts_coal_pkt_safe_drop */

int ts_get_ts_coal_pkt_tag(struct sk_buff *skb, BYTE *flag)
{
	if(ts_is_ts_coalesce_pkt(skb)==TS_FALSE) return TS_FALSE;
	*flag = (*(skb->data+skb->len-1));
	return TS_TRUE;
} /* ts_get_ts_coal_pkt_tag */

static BYTEx2 * ts_get_ts_coal_pkt_len_offset(struct sk_buff *skb)
{	return (BYTEx2 *)(skb->data+skb->len-6); }

static int ts_chk_coal_pkt_tag(BYTE flag, int packet_type)
{	if(packet_type == TS_FLAG_COAL)
	{	if( (flag & TS_FLAG_COAL)==TS_FLAG_COAL ) return TS_TRUE; }
   return TS_FALSE;
}

static int ts_set_coal_pkt_tag(BYTE *flag, int packet_type)
{
	if(packet_type == TS_FLAG_COAL)
	{	(*flag) |= TS_FLAG_COAL; }
   return TS_FALSE;
}

int ts_get_ts_coal_pkt_len(struct sk_buff *skb, BYTEx2 *len)
{
	if(ts_is_ts_coalesce_pkt(skb)==TS_FALSE) return TS_FALSE;
	*len = ntohs(*ts_get_ts_coal_pkt_len_offset(skb));
	return TS_TRUE;
} /* ts_get_ts_coal_pkt_len */

