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
#ifndef _TS_CONFIG_H
#define _TS_CONFIG_H
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/spinlock.h>
#include <net/inet_sock.h>
#include <net/snmp.h>

#define IN
#define OUT
#define INOUT

#define ZERO 0

#define IPPROTO_TS_ICMP		200
#define IPPROTO_TS_TCP		201
#define IPPROTO_TS_UDP		202
#define IPPROTO_TS_SCTP		203

#define TS_TRUE    1
#define TS_FALSE   0
#define TS_ERROR   0
#define TS_FALSE2 -1
#define TS_DROP   -3

#define MODE_NONE   0
#define MODE_ROUTER 1
#define MODE_BRIDGE 2
#define MODE_LOCAL  3
#define MODE_ROUTER_LOCAL 4
#define MODE_SIMULATE 5

#define TS_MAX_OPT_BUF_LEN 	3000
#define TS_MAX_OPT_BUF_LENx2  6000
#define TS_MAX_OPT_BUF_LENx3  9000

#define OPT_FLOW   1
#define UNOPT_FLOW 2

typedef unsigned char  	BYTE;
typedef unsigned short 	BYTEx2;
typedef __u32  BYTEx4;
typedef __u64	BYTEx8;


//TS Packet last byte flags (8bit flags)
#define TS_FLAG_COMP      0x01
#define TS_FLAG_HTTP      0x02
#define TS_FLAG_COAL	     0x04
#define TS_FLAG_TEMPL	  0x08
#define TS_FLAG_TEMPL_GENERIC	0x10
#define TS_FLAG_TEMPL_COMMON	0x20
#define TS_FLAG_SRCPORT_HTTP	0x40
#define TS_FLAG_SRCPORT_DNS	0x80
#define TS_FLAG_SIZE 1

//TCP/UDP known App. Ports
#define PROTO_HTTP    0x0050
#define PROTO_FTP     0x0015
#define PROTO_NFS     0x0801
#define PROTO_MYSQL   0x0cea
#define PROTO_PGSQL   0x1538
#define PROTO_SSH     0x0016
#define PROTO_SMTP    0x0019
//TLSv1, SSL, HTTPS, etc (port: 443)
#define PROTO_SSL	    0x01bb
#define PROTO_POP	    0x006e
#define PROTO_DNS	    0x0035
#define PROTO_SSDP    0x076c
#define PROTO_TELNET  0x0017
#define PROTO_IMAP    0x008f
//IMAP-over SSL
#define PROTO_IMAPS   0x03e1
#define PROTO_LDAP    0x0185
#define PROTO_KRB     0x0058
#define PROTO_SIP     0x13c4
#define PROTO_SIP2    0x13e2
#define PROTO_SMB     0x01bd

//Templating proto-id
#define PROTO_ID_HTTP    1
#define PROTO_ID_SQUID   1
#define PROTO_ID_FTP     2
#define PROTO_ID_NFS     3
#define PROTO_ID_MYSQL   4
#define PROTO_ID_PGSQL   5
#define PROTO_ID_SSH     6
#define PROTO_ID_SMTP    7
//TLSv1, SSL, HTTPS, etc (port: 443)
#define PROTO_ID_SSL	    8
#define PROTO_ID_POP	    9
#define PROTO_ID_DNS	    10
#define PROTO_ID_SSDP    11
#define PROTO_ID_TELNET  12
#define PROTO_ID_IMAP    13
//IMAP-over SSL
#define PROTO_ID_IMAPS   14
#define PROTO_ID_LDAP    15
#define PROTO_ID_KRB     16
#define PROTO_ID_SIP     17
#define PROTO_ID_SIP2    18
#define PROTO_ID_SMB     19

//Packet hook
#define TS_IP_FORWD		0
#define TS_BR_FORWD		1
#define TS_IP_BR_FORWD	2
#define TS_IP_OUTPUT		3
#define TS_IP_INPUT		4
#define TS_IP_SIMULATE	5

//Which packet (size) should be selected for optimization ?
//max reduction best-case: 4 -> 2+1 = 1 byte reduction. 
#define TS_PKT_OPT_THRESHOLD  4

typedef struct __remote_ip_ntwrk_t_ {
 BYTE network_id[4];
 BYTE subnet_msk[4];
 int en;
}remote_ip_ntwrk_t;

typedef struct __remote_ip_machine_t_ {
 BYTE ipaddr[4];
 int ignore_ip;
 int en;
}remote_ip_machine_t;

#define MAX_REMOTE_LIST 18

extern BYTEx2 PROTO_SQUID; //This is Read-write, hence it is variable and not #define !
extern int G_ts_mode;
extern int G_ts_mode_simu_en;

extern int G_ts_ip_fwd_nat_en;

extern int G_ts_r_ip_ntwrk_machine_en;
extern remote_ip_ntwrk_t r_ip_ntwrk_list[MAX_REMOTE_LIST];
extern remote_ip_machine_t r_ip_machine_list[MAX_REMOTE_LIST];

static DEFINE_SPINLOCK(ts_lan_port_lock);
static DEFINE_SPINLOCK(ts_wan_port_lock);
extern char G_ts_lan_port[IFNAMSIZ];
extern char G_ts_wan_port[IFNAMSIZ];

bool ts_skb_can_be_processed(struct sk_buff *skb);
bool ts_is_ts_pkt(struct sk_buff *skb);
int ts_pkt_safe_drop_or_send(struct sk_buff *skb, char *comment);
bool ts_chk_pkt_tag(BYTE flag, BYTE packet_type);

bool match_ip(BYTE *ip1, BYTE *ip2);
bool chk_pkt_remote_subnet_ip_list(u8 *dest_ip);
bool chk_pkt_remote_machine_ip_list(u8 *dest_ip);
bool compare_pkts_dest_ip(u8 *dest_ip, u8 *dest_ip2);
int chk_pkt_remote_subnet_ip_list_id(u8 *dest_ip);
int chk_pkt_remote_machine_ip_list_id(u8 *dest_ip);

#endif