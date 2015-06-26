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
#ifndef _TS_STATS_H
#define _TS_STATS_H
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

static DEFINE_SPINLOCK(ts_lan_stats_lock);
static DEFINE_SPINLOCK(ts_wan_stats_lock);
static DEFINE_SPINLOCK(ts_coal_stats_lock);

//#define COMPUTE_STATS 		1
//#define COMPUTE_NO_STATS 	0

typedef struct ts_stats_t_ {
 BYTEx4 lan_rx_bytes;
 BYTEx4 lan_tx_bytes;
 BYTEx4 wan_rx_bytes;
 BYTEx4 wan_tx_bytes;
}ts_stats_t;

typedef struct ts_coal_stats_t_ {
 BYTEx4 lan_rx_pkts;
 BYTEx4 lan_tx_pkts;
 BYTEx4 wan_rx_pkts;
 BYTEx4 wan_tx_pkts;
}ts_coal_stats_t;

#define MAX_IP_TCP_PROTO_STATS_TYPES 20
#define MAX_IP_UDP_PROTO_STATS_TYPES 20

typedef struct ts_ip_proto_stats_t_ {
 BYTEx4 tcp_pkt_cnt;
 BYTEx4 udp_pkt_cnt;
 BYTEx4 icmp_pkt_cnt;
 BYTEx4 sctp_pkt_cnt;
 BYTEx4 others_pkt_cnt;
}ts_ip_proto_stats_t;

typedef struct ts_proto_stats_t_ {
 BYTEx4 _ip_cnt;
 ts_ip_proto_stats_t ts_ip_proto_stats;
 BYTEx4 ip_tcp_app_other_cnt;
 BYTEx4 ip_udp_app_other_cnt;
}ts_proto_stats_t;

typedef struct __ts_pkt_sizes_stats_t_ {
 BYTEx4 in_pkt_cnt_0_63;
 BYTEx4 out_pkt_cnt_0_63;
 BYTEx4 in_pkt_cnt_64_127;
 BYTEx4 out_pkt_cnt_64_127;
 BYTEx4 in_pkt_cnt_128_255;
 BYTEx4 out_pkt_cnt_128_255;
 BYTEx4 in_pkt_cnt_256_511;
 BYTEx4 out_pkt_cnt_256_511;
 BYTEx4 in_pkt_cnt_512_1023;
 BYTEx4 out_pkt_cnt_512_1023;
 BYTEx4 in_pkt_cnt_1024_above;
 BYTEx4 out_pkt_cnt_1024_above;
}ts_pkt_sizes_stats_t;

typedef struct ts_filter_dns_stats_t_ {
 BYTEx4 lan_filter_dns_pkts;
 BYTEx4 wan_filter_dns_pkts;
 BYTEx4 lan_filter_dns_bytes_saved;
 BYTEx4 wan_filter_dns_bytes_saved;
}ts_filter_dns_stats_t;

#define TS_PKT_SIZES_STATS_MODE_IN    0
#define TS_PKT_SIZES_STATS_MODE_OUT   1 

//Egress or Ingress interface in or out -> IN, OUT
#define FLOW_IN   0
#define FLOW_OUT  1

extern ts_stats_t ts_oper_stats;
extern ts_coal_stats_t ts_coal_stats;
extern ts_pkt_sizes_stats_t ts_lan_pkt_sizes_stats;
extern ts_pkt_sizes_stats_t ts_wan_pkt_sizes_stats;
extern ts_proto_stats_t ts_lan_proto_stats;
extern ts_proto_stats_t ts_wan_proto_stats;
extern ts_filter_dns_stats_t ts_filter_dns_stats;

void ts_update_lan_stats(unsigned int rx_len, struct sk_buff *skb);
void ts_update_lan_stats_drop_pkt(unsigned int rx_len);
void ts_update_wan_stats(unsigned int rx_len, struct sk_buff *skb);
void ts_update_wan_stats_drop_pkt(unsigned int rx_len);
void ts_update_coal_lan_stats(int flow);
void ts_update_coal_wan_stats(int flow);
void ts_update_pkt_sizes_stats(unsigned int len, ts_pkt_sizes_stats_t *p, int mode_in_out);
void ts_get_proto_stats(struct sk_buff *skb, ts_proto_stats_t *ts_proto_stats);
#endif