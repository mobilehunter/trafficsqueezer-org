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
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/net.h>
#include <linux/if_ether.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/sctp.h>
#include <linux/netfilter_ipv4.h>
#include <net/checksum.h>
#include <linux/route.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <linux/ctype.h>
#include <linux/gfp.h>
#include <net/trafficsqueezer/core.h>
#include <net/trafficsqueezer/skbuff.h>

void ts_set_coalesce_ip_tos(struct sk_buff *skb) { ip_hdr(skb)->tos |= IPTOS_THROUGHPUT; }

bool ts_check_coalesce_ip_tos(struct sk_buff *skb)
{
  if( (ip_hdr(skb)->tos & IPTOS_THROUGHPUT)==IPTOS_THROUGHPUT ) { return true; } 
  return false;
}

BYTE * ts_get_ip_dest_ip_addr(struct sk_buff *skb) { return (BYTE *)&(ip_hdr(skb)->daddr); }
BYTE * ts_get_ip_source_ip_addr(struct sk_buff *skb) { return (BYTE *)&(ip_hdr(skb)->saddr); }
unsigned int ts_get_tcp_hdr_size(struct sk_buff *skb) { return (unsigned int)(tcp_hdr(skb)->doff*4); }
unsigned int ts_get_udp_hdr_size(struct sk_buff *skb) { return (unsigned int)(sizeof(struct udphdr)); }

unsigned int ts_get_tcp_pyld_size(struct sk_buff *skb)
{ return (unsigned int) ((skb->len)-ip_hdrlen(skb)-ts_get_tcp_hdr_size(skb)); }

unsigned int ts_get_udp_pyld_size(struct sk_buff *skb)
{ return	(unsigned int) ((skb->len)-ip_hdrlen(skb)-ts_get_udp_hdr_size(skb)); }

void ts_update_ip_tot_len(struct sk_buff *skb)
{  ip_hdr(skb)->tot_len = htons(skb->len);
	skb->ts_ip_pyld_size=ts_get_ip_pyld_size(skb);
}

void ts_ip_send_check(struct sk_buff *skb)
{
	ts_update_ip_tot_len(skb);
	{
		struct iphdr *ip = ip_hdr(skb);
		ip->check = 0x0000;
		ip->check = ip_fast_csum((unsigned char *)ip, ip->ihl);
	}
}

static void __ts_get_tcp_proto_port(__be16 port, __be16 *proto_port)
{	if(port==PROTO_HTTP || port==PROTO_SQUID || port==PROTO_FTP || port==PROTO_SMTP || port==PROTO_SSH || \
		port==PROTO_SSL || port==PROTO_POP || port==PROTO_MYSQL || port==PROTO_PGSQL || port==PROTO_TELNET || \
		port==PROTO_IMAP || port==PROTO_IMAPS || port==PROTO_LDAP || port==PROTO_KRB || port==PROTO_SIP || \
		port==PROTO_SIP2 || port==PROTO_SMB )
	{	*proto_port=port; }
	else { *proto_port = 0x0000; }
}

static void __ts_get_udp_proto_port(__be16 port, __be16 *proto_port)
{	if(port==PROTO_DNS || port==PROTO_SSDP) { *proto_port=port; }
	else { *proto_port = 0x0000; }
}

static void __ts_get_sctp_proto_port(__be16 port, __be16 *proto_port)
{	if(port==PROTO_HTTP || port==PROTO_SQUID || port==PROTO_FTP || port==PROTO_SMTP || port==PROTO_SSH || \
		port==PROTO_SSL || port==PROTO_POP || port==PROTO_MYSQL || port==PROTO_PGSQL || port==PROTO_TELNET || \
		port==PROTO_IMAP || port==PROTO_IMAPS || port==PROTO_LDAP || port==PROTO_KRB || port==PROTO_SIP || \
		port==PROTO_SIP2 || port==PROTO_SMB || \
		port==PROTO_DNS || port==PROTO_SSDP )
	{	*proto_port=port; }
	else { *proto_port = 0x0000; }
}

static __be16 __select_port(__be16 src_proto_port, __be16 dest_proto_port)
{
	if(src_proto_port!=0x0000 && dest_proto_port!=0x0000) 
	{ if(src_proto_port==dest_proto_port) return dest_proto_port; else return 0x0000; }
	else if(src_proto_port!=0x0000 && dest_proto_port==0x0000) { return src_proto_port; }
	else if(src_proto_port==0x0000 && dest_proto_port!=0x0000) { return dest_proto_port; }

	return 0x0000;
}

static __be16 __tcp_proto_port(struct sk_buff *skb)
{
	__be16 src_proto_port = 0x0000;
	__be16 dest_proto_port = 0x0000;

	//May be a non TCP packet ?
	if(skb->ts_ip_pyld_size<20) return 0x0000;
	
	//the skb is not yet Transport Header ready in non-IPv4 skb stack context-access.
	//  Hence do not use tcp_hdr(skb) to get transport header
	//  - also it may be a fragmented packet's fragment too !
	//NOTE: Even approximate guess also will do !!
	struct tcphdr *th = (struct tcphdr *)skb->ts_ip_pyld;
	__ts_get_tcp_proto_port( htons(th->source), &src_proto_port);
	__ts_get_tcp_proto_port( htons(th->dest), &dest_proto_port);
	
	if(src_proto_port==PROTO_HTTP) { skb->ts_srcproto_port=PROTO_HTTP; }
  		
	return __select_port(src_proto_port, dest_proto_port);
}

static __be16 __udp_proto_port(struct sk_buff *skb)
{	__be16 src_proto_port = 0x0000;
	__be16 dest_proto_port = 0x0000;
	
	//May be a non UDP packet ?
	if(skb->ts_ip_pyld_size<8) return 0x0000;
	
	//the skb is not yet Transport Header ready in non-IPv4 skb stack context-access.
	//  Hence do not use tcp_hdr(skb) to get transport header
	//  - also it may be a fragmented packet's fragment too !
	//NOTE: Even approximate guess also will do !!
	struct udphdr *uh = (struct udphdr *)skb->ts_ip_pyld;
	__ts_get_udp_proto_port( htons(uh->source), &src_proto_port);
	__ts_get_udp_proto_port( htons(uh->dest), &dest_proto_port);
	
	if(src_proto_port==PROTO_DNS) { skb->ts_srcproto_port=PROTO_DNS; }

	return __select_port(src_proto_port, dest_proto_port);
}

static __be16 __sctp_proto_port(struct sk_buff *skb)
{
	__be16 src_proto_port = 0x0000;
	__be16 dest_proto_port = 0x0000;

	//May be a non SCTP packet ?
	if(skb->ts_ip_pyld_size<36) return 0x0000;
	
	//the skb is not yet Transport Header ready in non-IPv4 skb stack context-access.
	//  Hence do not use sctp_hdr(skb) to get transport header
	//  - also it may be a fragmented packet's fragment too !
	//NOTE: Even approximate guess also will do !!
	struct sctphdr *sh = (struct sctphdr *)skb->ts_ip_pyld;
	__ts_get_sctp_proto_port( htons(sh->source), &src_proto_port);
	__ts_get_sctp_proto_port( htons(sh->dest), &dest_proto_port);
	
	if(src_proto_port==PROTO_HTTP) { skb->ts_srcproto_port=PROTO_HTTP; }
	else if(src_proto_port==PROTO_DNS) { skb->ts_srcproto_port=PROTO_DNS; }
  		
	return __select_port(src_proto_port, dest_proto_port);
}


//Return the payload size of the IP header
unsigned int ts_get_ip_pyld_size(struct sk_buff *skb)
{ return (unsigned int) (((unsigned int) ntohs(ip_hdr(skb)->tot_len)) - ip_hdrlen(skb)); }

//Return the Layer-2 (MAC Header) size
unsigned int ts_get_l2_hdr_size(struct sk_buff *skb)
{ return (unsigned int) (skb->len-skb->data_len); }

static bool ts_skb_has_frags(struct sk_buff *skb)
{
	if(skb_shinfo(skb)->nr_frags) return true;
	//if(skb_shinfo(skb)->nr_frags || skb_has_frags(skb) || skb->data_len!=0) return true;

	return false;
}

bool ts_skb_make_writable(struct sk_buff *skb)
{
	if(!skb_make_writable(skb, skb->len)) return false;
	return true;
}

bool ts_skb_safe_trim(struct sk_buff *skb, unsigned int len)
{
	if(!ts_skb_has_frags(skb)) { skb_trim(skb, len); }
	else {  if(___pskb_trim(skb, len)<0) return false; }
	skb->ts_ip_pyld=skb->data+(skb->ts_ip_hdr_size);
	return true;
}

bool ts_skb_safe_put(struct sk_buff *skb, unsigned int len)
{	if(len>skb_tailroom(skb))
   {  struct sk_buff *trailer; int err;
		if ((err = skb_cow_data(skb, skb->len + len, &trailer)) < 0) return false;
		skb_put(skb, len);
	}
	else
	{ skb_put(skb, len); }
	skb->ts_ip_pyld=skb->data+(skb->ts_ip_hdr_size);
	return true;
}

bool ts_skb_dev_lan(struct sk_buff *skb)
{	bool ret=false;
	spin_lock(&ts_lan_port_lock);
	if(!strcmp(skb->dev->name, G_ts_lan_port)) ret=true;
	spin_unlock(&ts_lan_port_lock);
	
   return ret;
}

bool ts_skb_dev_wan(struct sk_buff *skb)
{	bool ret=false;
	spin_lock(&ts_wan_port_lock);
	if(!strcmp(skb->dev->name, G_ts_wan_port)) ret=true;
	spin_unlock(&ts_wan_port_lock);
	
   return ret;
}

void reset_ts_skb(struct sk_buff *skb)
{
	skb->ts_ipproto=0x00;
	skb->ts_proto_port=0x0000;
	skb->ts_srcproto_port=0x0000;
	skb->ts_ip_hdr_size=0;
	skb->ts_ip_pyld_size=0;
	skb->ts_ip_hdr=NULL;
	skb->ts_ip_pyld=NULL;
	skb->ts_l2_pyld=NULL;
	skb->ts_l2_hdr_size=0;
}

bool ts_parse_pkt(struct sk_buff *skb, char *flow)
{	
	reset_ts_skb(skb);
	if(!strcmp(skb->dev->name,"lo")) return false;
	if(ip_is_fragment(ip_hdr(skb)))
	{	
		#ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
		printk("IP Fragmented packet !\n");
		#endif
	}
	if(skb->protocol==htons(ETH_P_IP))
	{	skb->ts_l2_hdr_size=(skb->len)-ntohs(ip_hdr(skb)->tot_len);
		skb->ts_ip_hdr=ip_hdr(skb);
		skb->ts_ipproto=skb->ts_ip_hdr->protocol;
		skb->ts_l2_pyld=(unsigned char *)ip_hdr(skb);
		skb->ts_ip_hdr_size=ip_hdrlen(skb);
		skb->ts_ip_pyld_size=ts_get_ip_pyld_size(skb);
		skb->ts_ip_pyld=(unsigned char *)(skb->ts_l2_pyld+(size_t)skb->ts_ip_hdr_size);

		if(skb->ts_ipproto==IPPROTO_TS_TCP||skb->ts_ipproto==IPPROTO_TS_UDP||skb->ts_ipproto==IPPROTO_TS_ICMP||skb->ts_ipproto==IPPROTO_TS_SCTP)
		{ /* do nothing, but allow this packet */ }
		else if(skb->ts_ipproto==IPPROTO_ICMP)
		{ /* do nothing, but allow this packet */ }
		else if(skb->ts_ipproto==IPPROTO_SCTP)
		{  skb->ts_proto_port=__sctp_proto_port(skb); }
		else if(skb->ts_ipproto==IPPROTO_TCP) 
		{	skb->ts_proto_port=__tcp_proto_port(skb); }
		else if(skb->ts_ipproto==IPPROTO_UDP)
		{	skb->ts_proto_port=__udp_proto_port(skb); }
		else { return false; }
	}
	else if(skb->protocol==htons(ETH_P_IPV6))
	{	return false;
	}
	else { return false; }

#ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
	printk("%s %s) ethproto:%d ipproto:%d proto_port:%d ", skb->dev->name, flow, skb->ts_ethproto, skb->ts_ipproto, skb->ts_proto_port);
	printk("ts_ip_hdr_size:%d ip_pyld_size:%d \n", skb->ts_ip_hdr_size, skb->ts_ip_pyld_size);
#endif

	return true;
}
