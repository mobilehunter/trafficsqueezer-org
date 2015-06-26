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
#ifndef _TS_COAL_H_
#define _TS_COAL_H_
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
#include <net/trafficsqueezer/skbuff.h>
#include <net/trafficsqueezer/comp.h>
#include <net/trafficsqueezer/engine.h>

extern int GROV_ts_coal_en;
extern int G_ts_coal_proto_dns_en;
extern int GROV_ts_coal_bucket_timer_delay;
extern int GROV_ts_coal_bucket_size;

//-------------TS Traffic Coalescing Optimization----------------------------------
#define V_C_MAX_ADDITIONAL_BUCKET_PDU_SIZE_V_C	1600  /* A bucket can hold a max. bytes */
#define TS_OPERATION_TS_COALESCE 	0
#define TS_OPERATION_TS_UNCOALESCE 	1

typedef struct __ts_skb_coal_bucket_t_ {
	struct sk_buff *stored_skb;
	
	//If pkt_remote_subnet_ip_list_id is -1 and pkt_remote_subnet_ip_list_id==-1, then it contains no packet !
	int pkt_remote_subnet_ip_list_id;
	int pkt_remote_machine_ip_list_id;
	int enabled;
}ts_skb_coal_bucket_t;

extern ts_skb_coal_bucket_t ts_coal_ip_output_bkt;
extern ts_skb_coal_bucket_t ts_coal_ip_br_forward_bkt;

//(kernel timer data-structure)
extern struct timer_list ts_coal_ip_output_bkt_timer;
extern struct timer_list ts_coal_ip_br_forward_bkt_timer;

int ts_store_or_send(IN struct sk_buff *skb, int flow);
int ts_uncoal_or_send(IN struct sk_buff *skb, OUT struct sk_buff *skb2, int flow);
int ts_clean_bucket(ts_skb_coal_bucket_t *coal_bkt); //also called in system init (hence it is not a private api) !!
#endif
