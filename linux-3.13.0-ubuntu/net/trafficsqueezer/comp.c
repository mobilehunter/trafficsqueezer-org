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
#include <linux/ctype.h>
#include <linux/lz4.h>
#include <linux/lzo.h>
#include <net/trafficsqueezer/core.h>
#include <net/trafficsqueezer/comp.h>

void ts_comp(BYTE *flag, BYTE *pbuff, size_t *pbuff_len, BYTE *mid_buff, BYTE *lz4hc_wrkmem)
{	size_t mid_buff_size = 0;

	///if(lz4hc_compress( (const unsigned char *)pbuff, (*pbuff_len), (unsigned char *)mid_buff, &mid_buff_size, (void *)lz4hc_wrkmem)<0) return;
	if(lzo1x_1_compress( (const unsigned char *)pbuff, (*pbuff_len), (unsigned char *)mid_buff, &mid_buff_size, (void *)lz4hc_wrkmem)<0) return;
		
	if(((mid_buff_size+TS_FLAG_SIZE) < (*pbuff_len)) && (mid_buff_size!=0))
	{	memcpy((BYTE *)pbuff, (BYTE *)mid_buff, mid_buff_size); (*pbuff_len)=mid_buff_size; (*flag) |= TS_FLAG_COMP;
		#ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
		printk("comp - prossd [LZ4-HC] [mid_buff_size: %zu] [flag: %d]\n", mid_buff_size, *flag);
		#endif
	}
}

bool ts_decomp(BYTE *pbuff, size_t *pbuff_len, BYTE *mid_buff)
{  size_t mid_buff_size = TS_MAX_OPT_BUF_LEN;  //WARNING: DO NOT change this !!

	///if(lz4_decompress_unknownoutputsize( (const unsigned char *)pbuff, (*pbuff_len), (unsigned char *)mid_buff,  &mid_buff_size)<0) { return false; }
	if(lzo1x_decompress_safe( (const unsigned char *)pbuff, (*pbuff_len), (unsigned char *)mid_buff,  &mid_buff_size)<0) { return false; }
	if(mid_buff_size > TS_MAX_OPT_BUF_LEN) { return false; } 
	
	memcpy((BYTE *)pbuff, (BYTE *)mid_buff, mid_buff_size); (*pbuff_len)=mid_buff_size;
#ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
	printk("decomp - prossd [LZ4-HC] [mid_buff_size: %zu]\n", mid_buff_size);
#endif   
	return true;
}