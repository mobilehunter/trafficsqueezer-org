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
#include <linux/gfp.h>
#include <net/trafficsqueezer/core.h>
#include <net/trafficsqueezer/stats.h>
#include <net/trafficsqueezer/engine.h>
#include <net/trafficsqueezer/coal.h>
#include <net/trafficsqueezer/coal_core.h>
#include <net/trafficsqueezer/ip_coal_flow.h>
#include <net/trafficsqueezer/filter_dns.h>
#include <net/trafficsqueezer/dpi_pop.h>

int ts_ip_coalesce_rcv(struct sk_buff *skb, struct sk_buff *skb2)
{
	//Coalescing is not supported in simulation mode !
	if(G_ts_mode==MODE_SIMULATE) return ts_ts_coal_pkt_safe_drop(skb, "ts_ip_coalesce_rcv-1");
	
	//final super API to check this packet is eligible for TS processing ?
	if(ts_skb_can_be_coal_processed(skb)==TS_FALSE) return ts_ts_coal_pkt_safe_drop(skb, "ts_ip_coalesce_rcv-2");

    //if coalescing is disabled ? and this is not a coalesced packet ? then don't sent into engine !
    /// this should also prevent below unwanted stats calculation, when completely coalescing is disabled in this system.
    if( (ts_is_ts_coalesce_pkt(skb)==TS_FALSE) && (GROV_ts_coal_en == TS_FALSE) ) return ts_ts_coal_pkt_safe_drop(skb, "ts_ip_coalesce_rcv-5");

	//Un-Optimization
	ts_update_coal_wan_stats(FLOW_IN);
	int ret;
	ret = ts_unopt_coalesce_flow_engine(skb, skb2, TS_IP_INPUT);
	if(ret==TS_DROP) return ts_ts_coal_pkt_safe_drop(skb, "ts_ip_coalesce_rcv-6");
	ts_update_coal_wan_stats(FLOW_OUT);  //for skb (skb2 coal stats are calculated inside).
       
	return ts_ts_coal_pkt_safe_drop(skb, "ts_ip_coalesce_rcv-final-return");
} /* ts_ip_coalesce_rcv */


int ts_ip_coalesce_output(struct sk_buff *skb)
{
	int pkt_uncoalesced = TS_FALSE;
	
	///if(skb->ts_forward_pkt==1){return TS_TRUE;} //DO NOT PROCESS IT !! //DO NOT DROP IT !! (its not local packet)

	//Coalescing is not supported in simulation mode !
	if(G_ts_mode==MODE_SIMULATE) return ts_ts_coal_pkt_safe_drop(skb, "f_c_ts_ip_coalesce_output_f_c-1");	
	
	//final super API to check this packet is eligible for TS processing ? - send or drop if it is already TS packet !
	if(ts_skb_can_be_coal_processed(skb)==TS_FALSE) return ts_ts_coal_pkt_safe_drop(skb, "f_c_ts_ip_coalesce_output_f_c-2");
	
    //If already TS coalesced packet? Then DROP IT !   This packet may cause issues in other systems once it crosses TS machine !
    if(ts_is_ts_coalesce_pkt(skb)==TS_TRUE) return ts_ts_coal_pkt_safe_drop(skb, "f_c_ts_ip_coalesce_output_f_c-3");

	if(GROV_ts_coal_en==TS_FALSE) return ts_ts_coal_pkt_safe_drop(skb, "f_c_ts_ip_coalesce_output_f_c-4"); //Dont coalesce or continue beyond this point !

	ts_update_coal_lan_stats(FLOW_IN);
	if(ts_opt_coalesce_flow_engine(skb, TS_IP_OUTPUT)==TS_DROP) return TS_DROP;
	ts_update_coal_lan_stats(FLOW_OUT);
        
	//Outgoing packet meant to be an unoptimized packet ?
	if(pkt_uncoalesced == TS_TRUE)
		return ts_ts_coal_pkt_safe_drop(skb, "f_c_ts_ip_coalesce_output_f_c-final-return"); //Send or Drop the packet
	else
		return TS_TRUE; //Always Send
}

int ts_ip_br_coalesce_forward(struct sk_buff *skb, struct sk_buff *skb2, int flow, int operation)
{
    int pkt_unoptimized = TS_FALSE;
/*************
	 if(ts_pkt_to_wan(skb) && operation!=TS_OPERATION_TS_COALESCE) return TS_TRUE; //Skip this combination of flow
	 if(ts_pkt_to_lan(skb) && operation!=TS_OPERATION_TS_UNCOALESCE) return TS_TRUE; //Skip this combination of flow
    
   //final super API to check this packet is eligible for TS processing ? - forward or drop if it is already TS packet !
	if(ts_skb_can_be_coal_processed(skb)==TS_FALSE) return ts_ts_coal_pkt_safe_drop(skb, "ts_ip_br_coalesce_forward-1");

	//Perform TS Optimization
    if(ts_pkt_to_wan(skb) && operation==TS_OPERATION_TS_COALESCE)
	{
		//If already TS coalesced packet? Then DROP IT !   This packet may cause issues in other systems once it crosses TS machine !
   		if(ts_is_ts_coalesce_pkt(skb)==TS_TRUE) return ts_ts_coal_pkt_safe_drop(skb, "ts_ip_br_coalesce_forward-2");
   	
   		if(GROV_ts_coal_en == TS_FALSE) return ts_ts_coal_pkt_safe_drop(skb, "ts_ip_br_coalesce_forward-3"); //Dont coalesce or continue beyond this point !
   	
		ts_update_coal_lan_stats(FLOW_IN);
		if(ts_opt_coalesce_flow_engine(skb, flow)==TS_DROP) return TS_DROP;
		ts_update_coal_lan_stats(FLOW_OUT);
	}
	else if(ts_pkt_to_lan(skb) && operation==TS_OPERATION_TS_UNCOALESCE) //Perform TS Un-Optimization
	{
		ts_update_coal_wan_stats(FLOW_IN);
		
		//is it invoked via forward wan packet or just via forward lan packet during simulation ?
		int ret;
	   ret = ts_unopt_coalesce_flow_engine(skb, skb2, flow);
		if(ret==TS_DROP) return TS_DROP;
		ts_update_coal_wan_stats(FLOW_OUT);
	   pkt_unoptimized = TS_TRUE;
	}
**************/
	//Outgoing packet meant to be an unoptimized packet ?
	if(pkt_unoptimized == TS_TRUE)
		return ts_ts_coal_pkt_safe_drop(skb, "ts_ip_br_coalesce_forward-final-return"); //Forward or Drop the packet
	else
		return TS_TRUE; //Always forward
} EXPORT_SYMBOL_GPL(ts_ip_br_coalesce_forward); //IMPORTANT: Required for br_forward and other outer loosely coupled modules !
