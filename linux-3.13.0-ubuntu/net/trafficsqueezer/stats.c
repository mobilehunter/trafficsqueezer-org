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
#include <net/trafficsqueezer/core.h>
#include <net/trafficsqueezer/stats.h>

ts_stats_t ts_oper_stats; EXPORT_SYMBOL(ts_oper_stats);
ts_coal_stats_t ts_coal_stats; EXPORT_SYMBOL(ts_coal_stats);
ts_pkt_sizes_stats_t ts_lan_pkt_sizes_stats; EXPORT_SYMBOL(ts_lan_pkt_sizes_stats);
ts_pkt_sizes_stats_t ts_wan_pkt_sizes_stats; EXPORT_SYMBOL(ts_wan_pkt_sizes_stats);
ts_proto_stats_t ts_lan_proto_stats; EXPORT_SYMBOL(ts_lan_proto_stats);
ts_proto_stats_t ts_wan_proto_stats; EXPORT_SYMBOL(ts_wan_proto_stats);
ts_filter_dns_stats_t ts_filter_dns_stats; EXPORT_SYMBOL(ts_filter_dns_stats);

void ts_update_lan_stats(unsigned int rx_len, struct sk_buff *skb)
{	if(rx_len==skb->ts_ip_pyld_size) return;
	spin_lock(&ts_lan_stats_lock);
	ts_get_proto_stats(skb, &ts_lan_proto_stats);
	ts_oper_stats.lan_rx_bytes +=(BYTEx4)rx_len;
	ts_update_pkt_sizes_stats(rx_len, &ts_lan_pkt_sizes_stats, TS_PKT_SIZES_STATS_MODE_IN);
  	ts_oper_stats.lan_tx_bytes +=(BYTEx4)skb->ts_ip_pyld_size;
	ts_update_pkt_sizes_stats(skb->ts_ip_pyld_size, &ts_lan_pkt_sizes_stats, TS_PKT_SIZES_STATS_MODE_OUT);
	spin_unlock(&ts_lan_stats_lock);
}

void ts_update_lan_stats_drop_pkt(unsigned int rx_len)
{	spin_lock(&ts_lan_stats_lock);
	ts_oper_stats.lan_rx_bytes +=(BYTEx4)rx_len;
	ts_update_pkt_sizes_stats(rx_len, &ts_lan_pkt_sizes_stats, TS_PKT_SIZES_STATS_MODE_IN);
	spin_unlock(&ts_lan_stats_lock);
}

void ts_update_wan_stats(unsigned int rx_len, struct sk_buff *skb)
{	if(rx_len==skb->ts_ip_pyld_size) return;
	spin_lock(&ts_wan_stats_lock);
	ts_get_proto_stats(skb, &ts_wan_proto_stats);
  	ts_oper_stats.wan_rx_bytes +=(BYTEx4)rx_len;
	ts_update_pkt_sizes_stats(rx_len, &ts_wan_pkt_sizes_stats, TS_PKT_SIZES_STATS_MODE_IN);
  	ts_oper_stats.wan_tx_bytes +=(BYTEx4)skb->ts_ip_pyld_size;
	ts_update_pkt_sizes_stats(skb->ts_ip_pyld_size, &ts_wan_pkt_sizes_stats, TS_PKT_SIZES_STATS_MODE_OUT);
	spin_unlock(&ts_wan_stats_lock);
}

void ts_update_wan_stats_drop_pkt(unsigned int rx_len)
{	spin_lock(&ts_wan_stats_lock);
  	ts_oper_stats.wan_rx_bytes +=(BYTEx4)rx_len;
	ts_update_pkt_sizes_stats(rx_len, &ts_wan_pkt_sizes_stats, TS_PKT_SIZES_STATS_MODE_IN);
	spin_unlock(&ts_wan_stats_lock);
}

void ts_update_coal_lan_stats(int flow)
{	if(flow==FLOW_IN)
	{	spin_lock(&ts_coal_stats_lock);
		ts_coal_stats.lan_rx_pkts++;
		spin_unlock(&ts_coal_stats_lock);
	}
	else if(flow==FLOW_OUT)
	{	spin_lock(&ts_coal_stats_lock);
		ts_coal_stats.lan_tx_pkts++;
		spin_unlock(&ts_coal_stats_lock);
	}
}

void ts_update_coal_wan_stats(int flow)
{	if(flow==FLOW_IN)
	{	spin_lock(&ts_coal_stats_lock);
		ts_coal_stats.wan_rx_pkts++;
		spin_unlock(&ts_coal_stats_lock);
	}
	else if(flow==FLOW_OUT)
	{	spin_lock(&ts_coal_stats_lock);
		ts_coal_stats.wan_tx_pkts++;
		spin_unlock(&ts_coal_stats_lock);
	}
}

void ts_update_pkt_sizes_stats(unsigned int len, ts_pkt_sizes_stats_t *p, int mode_in_out)
{	if(mode_in_out==TS_PKT_SIZES_STATS_MODE_IN)
	{	if(len<64) { p->in_pkt_cnt_0_63++; }
		else if(len>=64 && len<128) { p->in_pkt_cnt_64_127++; }
		else if(len>=128 && len<256) { p->in_pkt_cnt_128_255++; }
		else if(len>=256 && len<512) { p->in_pkt_cnt_256_511++; }
   	else if(len>=512 && len<1024) { p->in_pkt_cnt_512_1023++; }
		else if(len>=1024) {	p->in_pkt_cnt_1024_above++; }
	}
	else if(mode_in_out==TS_PKT_SIZES_STATS_MODE_OUT)
	{	if(len<64) { p->out_pkt_cnt_0_63++; }
   	else if(len>=64 && len<128) { p->out_pkt_cnt_64_127++; }
   	else if(len>=128 && len<256) { p->out_pkt_cnt_128_255++; }
   	else if(len>=256 && len<512) { p->out_pkt_cnt_256_511++; }
   	else if(len>=512 && len<1024) { p->out_pkt_cnt_512_1023++; }
   	else if(len>=1024) { p->out_pkt_cnt_1024_above++; }
	}
}

void ts_get_proto_stats(struct sk_buff *skb, ts_proto_stats_t *ts_proto_stats)
{	if(skb->protocol==htons(ETH_P_IP))
	{ ts_proto_stats->_ip_cnt++; 
		if(skb->ts_ipproto==IPPROTO_TCP || skb->ts_ipproto==IPPROTO_TS_TCP) { ts_proto_stats->ts_ip_proto_stats.tcp_pkt_cnt++; }
		else if(skb->ts_ipproto==IPPROTO_UDP || skb->ts_ipproto==IPPROTO_TS_UDP) { ts_proto_stats->ts_ip_proto_stats.udp_pkt_cnt++; }
		else if(skb->ts_ipproto==IPPROTO_ICMP || skb->ts_ipproto==IPPROTO_TS_ICMP) { ts_proto_stats->ts_ip_proto_stats.icmp_pkt_cnt++; }
		else if(skb->ts_ipproto==IPPROTO_SCTP || skb->ts_ipproto==IPPROTO_TS_SCTP) { ts_proto_stats->ts_ip_proto_stats.sctp_pkt_cnt++; }
	}
}