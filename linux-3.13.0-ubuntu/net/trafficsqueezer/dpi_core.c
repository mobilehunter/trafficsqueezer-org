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
#include <net/trafficsqueezer/dpi_core.h>
#include <net/trafficsqueezer/memreplace.h>
#include <net/trafficsqueezer/stats.h>

int GROV_ts_dpi_en=TS_FALSE; EXPORT_SYMBOL(GROV_ts_dpi_en);

//Check printable ASCII range found in a custom buffer (binary and ascii buffer) ?

int ts_found_printable_ascii(unsigned char *buff, size_t bufflen, int is_domain_name)
{
	int k;
	unsigned char ascii_start = 32; // 'space'
	unsigned char ascii_end = 126; // '~'
	if(is_domain_name==TS_TRUE) //range with no spaces and no '~' for domain names
	{
		ascii_start = 45; // '-' 
		ascii_end = 122;  // 'z'
	}

	if(bufflen<=0) return TS_FALSE;
	if(buff==NULL) return TS_FALSE;
	
	for(k=0;k<bufflen;k++)
	{
		if(is_domain_name==TS_TRUE) //should not contain these characters in Domain names
		{
			if(buff[k]=='/' || buff[k]==':' || buff[k]==';' || buff[k]=='<' || \
			   buff[k]=='>' || buff[k]==',' || buff[k]=='?' || buff[k]=='@' ||  \
				buff[k]=='[' || buff[k]==']' || buff[k]=='\\' || buff[k]=='`')
			{
				return TS_FALSE;
			}
		}
		
		if(buff[k] >= ascii_start && buff[k] <= ascii_end)
		{
			//do nothing	
		}
		else
		{
			return TS_FALSE;
		}
		
	}
	return TS_TRUE;
} /*ts_found_printable_ascii */ 



int dpi_parse_buffer(IN unsigned char *buff, IN size_t bufflen, IN unsigned char *start, IN unsigned char *end, OUT unsigned char *out_buff, OUT size_t *out_bufflen )
{
	unsigned char *from_start = NULL;
	
	if(buff==NULL) return TS_FALSE;
	if(out_buff==NULL) return TS_FALSE;
	if(start==NULL) return TS_FALSE;
	if(end==NULL) return TS_FALSE;
	if(bufflen==0) return TS_FALSE;
	out_buff[0] = '\0';
	
   from_start =  (unsigned char *)ts_memmem((unsigned char *)buff, bufflen,  (unsigned char *)start, strlen(start)); 
	if(from_start==NULL) { return TS_FALSE; }
	
	unsigned char *from_end = NULL;
   from_end = ts_memmem(from_start, bufflen - (from_start-buff), end, strlen(end)); 
	if(from_end==NULL) { return TS_FALSE; }
	
	//Increment from_start and ignore "from: "
	from_start += strlen(start);
	
	//Looks like we got a valid domain, so capture and save the same
	*out_bufflen = (size_t *)(from_end-from_start);
	
	//Check if it is out of bounds, before store and sent
	if( (*out_bufflen) > 98 ) {  return TS_FALSE; }

	//Instead of memcpy, do the below safe buffer copy !!
	int k=0;
	for(k=0;k<(*out_bufflen);k++)
	{
		if(from_start[k]==' ') { out_buff[k]='\0'; break; }
		if(from_start[k]==',') { out_buff[k]=';'; } //we use ',' as
		if(k==49) { out_buff[k]='\0'; break; } //chop the content if it is > 50 characters to 50 characters !!
		out_buff[k] = from_start[k];
	}
	out_buff[k]='\0';
	
	//Check printable ASCII range ?	
	if(ts_found_printable_ascii( out_buff, strlen(out_buff), IS_NON_DOMAIN)==TS_FALSE) { return TS_FALSE; }
	
	return TS_TRUE;
} /* dpi_parse_buffer */
