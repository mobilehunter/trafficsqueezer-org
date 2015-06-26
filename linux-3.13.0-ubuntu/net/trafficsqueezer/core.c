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
#include <linux/bootmem.h>
#include <net/trafficsqueezer/core.h>
#include <net/trafficsqueezer/skbuff.h>

BYTEx2 PROTO_SQUID = 0x0c38; EXPORT_SYMBOL(PROTO_SQUID);  //This is Read-write, hence it is variable and not #define !

int G_ts_mode=MODE_NONE; EXPORT_SYMBOL(G_ts_mode);
int G_ts_ip_fwd_nat_en=TS_FALSE; EXPORT_SYMBOL(G_ts_ip_fwd_nat_en);
char G_ts_lan_port[IFNAMSIZ]={'n','o','n','e',0x00}; EXPORT_SYMBOL(G_ts_lan_port);
char G_ts_wan_port[IFNAMSIZ]={'n','o','n','e',0x00}; EXPORT_SYMBOL(G_ts_wan_port);

int G_ts_r_ip_ntwrk_machine_en = TS_TRUE; EXPORT_SYMBOL(G_ts_r_ip_ntwrk_machine_en);
remote_ip_ntwrk_t  r_ip_ntwrk_list[MAX_REMOTE_LIST]; EXPORT_SYMBOL(r_ip_ntwrk_list);
remote_ip_machine_t  r_ip_machine_list[MAX_REMOTE_LIST]; EXPORT_SYMBOL(r_ip_machine_list);

bool ts_skb_can_be_processed(struct sk_buff *skb)
{
	if(!(ts_skb_dev_wan(skb) || ts_skb_dev_lan(skb))) return false;
	if(skb->len>TS_MAX_OPT_BUF_LEN) return false;
	if(!ts_skb_make_writable(skb)) return false;
	ts_parse_pkt(skb, "]]Int-SKB-Sync-Vars[[");
	return true;
}

bool ts_is_ts_pkt(struct sk_buff *skb)
{
  if(skb->ts_ipproto==IPPROTO_TS_TCP || skb->ts_ipproto==IPPROTO_TS_UDP || skb->ts_ipproto==IPPROTO_TS_ICMP || skb->ts_ipproto==IPPROTO_TS_SCTP) return true;
  return false;
}

//Do not allow a TS packet into TCP/IP Stack !
int ts_pkt_safe_drop_or_send(struct sk_buff *skb, char *comment)
{
	if(comment==NULL) return TS_TRUE;
	if(skb==NULL) { printk("Already packet is dropped [flow: %s]\n", comment); return TS_DROP; }
	
	if(ts_is_ts_pkt(skb)) //Seems it is still a TS packet  
	{
		kfree_skb(skb);
		printk("Cowardly safe dropping a TS packet [flow: %s]\n", comment);
		return TS_DROP;
	}
	
	return TS_TRUE;
} /* ts_pkt_safe_drop_or_send */

bool ts_chk_pkt_tag(BYTE flag, BYTE packet_type)
{
  if( (flag & packet_type)==packet_type ) return true;
  return false;
}

bool match_ip(BYTE *ip1, BYTE *ip2)
{
	if((ip1[0]==ip2[0]) && (ip1[1]==ip2[1]) && (ip1[2]==ip2[2]) && (ip1[3]==ip2[3])) { return true; }
	return false;
}

bool chk_pkt_remote_subnet_ip_list(u8 *dest_ip)
{  int i;
   for(i=0; i<MAX_REMOTE_LIST; i++)
   {
      if(r_ip_ntwrk_list[i].en)
      {
         if((((*(dest_ip+0)) & r_ip_ntwrk_list[i].subnet_msk[0]) == r_ip_ntwrk_list[i].network_id[0]) && \
            (((*(dest_ip+1)) & r_ip_ntwrk_list[i].subnet_msk[1]) == r_ip_ntwrk_list[i].network_id[1]) && \
            (((*(dest_ip+2)) & r_ip_ntwrk_list[i].subnet_msk[2]) == r_ip_ntwrk_list[i].network_id[2]) && \
            (((*(dest_ip+3)) & r_ip_ntwrk_list[i].subnet_msk[3]) == r_ip_ntwrk_list[i].network_id[3]) )
         { return true; }
      }
   }
   return false;
}

bool chk_pkt_remote_machine_ip_list(u8 *dest_ip)
{	 int i;
	 for(i=0; i<MAX_REMOTE_LIST; i++)
	 {
	     if(r_ip_machine_list[i].en)
	     {
	        if( (r_ip_machine_list[i].ipaddr[0]==(*(dest_ip+0)))  && (r_ip_machine_list[i].ipaddr[1]==(*(dest_ip+1))) && \
	            (r_ip_machine_list[i].ipaddr[2]==(*(dest_ip+2))) && (r_ip_machine_list[i].ipaddr[3]==(*(dest_ip+3))))
	        {   if(r_ip_machine_list[i].ignore_ip) { return TS_FALSE; }
	            return true;
	        }
	     }
	 }
	 return false;
}

bool compare_pkts_dest_ip(u8 *dest_ip, u8 *dest_ip2)
{
	if(((*(dest_ip+0))==(*(dest_ip2+0))) && ((*(dest_ip+1))==(*(dest_ip2+1))) && \
		((*(dest_ip+2))==(*(dest_ip2+2))) && ((*(dest_ip+3))==(*(dest_ip2+3))))
   {  return true; }
   return false;
}


//Get the type of remote ip list which matches ? !!
////This is required for coalescing, to match the packet flow specific to remote subnet.
int chk_pkt_remote_subnet_ip_list_id(u8 *dest_ip)
{  int i;

	//If remote network list check is not enabled, then return some default number !
	//// this matches all packets, and all packets contains same destination !!
	if(G_ts_r_ip_ntwrk_machine_en==TS_FALSE) return 100;

   for(i=0; i<MAX_REMOTE_LIST; i++)
   {
        if(r_ip_ntwrk_list[i].en)
        {
             if( (((*(dest_ip+0)) & r_ip_ntwrk_list[i].subnet_msk[0]) == r_ip_ntwrk_list[i].network_id[0]) && \
                 (((*(dest_ip+1)) & r_ip_ntwrk_list[i].subnet_msk[1]) == r_ip_ntwrk_list[i].network_id[1]) && \
                 (((*(dest_ip+2)) & r_ip_ntwrk_list[i].subnet_msk[2]) == r_ip_ntwrk_list[i].network_id[2]) && \
                 (((*(dest_ip+3)) & r_ip_ntwrk_list[i].subnet_msk[3]) == r_ip_ntwrk_list[i].network_id[3]) )
             {
                 return i;
             }
        }
   }
   return -1;
}


//Get the type of remote ip list which matches ? !!
////This is required for coalescing, to match the packet flow specific to remote machine.
int chk_pkt_remote_machine_ip_list_id(u8 *dest_ip)
{  int i;

	//If remote network list check is not enabled, then return some default number !
	//// this matches all packets, and all packets contains same destination !!
	if(G_ts_r_ip_ntwrk_machine_en==TS_FALSE) return 100;

   for(i=0; i<MAX_REMOTE_LIST; i++)
   {
       if(r_ip_machine_list[i].en)
       {
           if( (r_ip_machine_list[i].ipaddr[0]==(*(dest_ip+0)))  && (r_ip_machine_list[i].ipaddr[1]==(*(dest_ip+1))) && \
               (r_ip_machine_list[i].ipaddr[2]==(*(dest_ip+2))) && (r_ip_machine_list[i].ipaddr[3]==(*(dest_ip+3))))
           { //Ignore this ?
             if(r_ip_machine_list[i].ignore_ip) { return -1; }
             return i;
           }
       }
   }
   return -1;
}