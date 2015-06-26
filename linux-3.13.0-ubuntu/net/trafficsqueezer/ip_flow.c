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
#include <linux/ctype.h>
#include <linux/gfp.h>
#include <net/trafficsqueezer/core.h>
#include <net/trafficsqueezer/stats.h>
#include <net/trafficsqueezer/dpi_l7filter_hooks.h>
#include <net/trafficsqueezer/engine.h>
#include <net/trafficsqueezer/ip_flow.h>
#include <net/trafficsqueezer/filter_dns.h>

int ts_netif_receive_skb(struct sk_buff *skb)
{
	if(!ts_parse_pkt(skb, "<<IN")) return ts_pkt_safe_drop_or_send(skb, "ts_netif_receive_skb-0");
	if(!ts_skb_can_be_processed(skb)) return ts_pkt_safe_drop_or_send(skb, "ts_netif_receive_skb-1");
	if(G_ts_mode==MODE_SIMULATE) { ts_opt(skb); }

	unsigned int rx_len = skb->ts_ip_pyld_size;
	unsigned int skb_len = skb->len;
	if(ts_unopt(skb)==TS_DROP) { ts_update_wan_stats_drop_pkt(skb_len); return TS_DROP; }
 	//////////if(ts_dpi_l7filter_hook(skb)==TS_DROP) { ts_update_wan_stats_drop_pkt(skb_len); return TS_DROP; }
	ts_update_wan_stats(rx_len, skb);
	
	return ts_pkt_safe_drop_or_send(skb, "ts_netif_receive_skb-final-return");
} EXPORT_SYMBOL_GPL(ts_netif_receive_skb);

int ts_dev_queue_xmit(struct sk_buff *skb)
{	unsigned int rx_len=skb->len;
	if(!ts_parse_pkt(skb, ">>OUT")) return ts_pkt_safe_drop_or_send(skb, "ts_dev_queue_xmit-0");
	if(!ts_skb_can_be_processed(skb)) return ts_pkt_safe_drop_or_send(skb, "ts_dev_queue_xmit-1");
	
 	//////////if(ts_dpi_l7filter_hook(skb)==TS_DROP) { ts_update_lan_stats_drop_pkt(rx_len); return TS_DROP; }

 	//when to optimize ?
	if( (G_ts_mode==MODE_BRIDGE || G_ts_mode==MODE_ROUTER || G_ts_mode==MODE_ROUTER_LOCAL) && ts_skb_dev_wan(skb)) { /* continue */ }
	else if(G_ts_mode==MODE_LOCAL || G_ts_mode==MODE_SIMULATE) { /* continue */ }
	else { return ts_pkt_safe_drop_or_send(skb, "ts_dev_queue_xmit-2"); }
		
	rx_len = skb->ts_ip_pyld_size;
	ts_opt(skb);
	ts_update_lan_stats(rx_len, skb);

	if(G_ts_mode==MODE_SIMULATE)
	{	if(ts_unopt(skb)==TS_DROP) return TS_DROP;
		return ts_pkt_safe_drop_or_send(skb, "ts_dev_queue_xmit-final-return"); //Send or Drop the packet
	}
	
	return TS_TRUE; //Always Send
} EXPORT_SYMBOL_GPL(ts_dev_queue_xmit);
