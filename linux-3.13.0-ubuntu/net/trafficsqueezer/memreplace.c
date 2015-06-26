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
#include <linux/ctype.h>
#include <linux/gfp.h>
#include <net/trafficsqueezer/core.h>
#include <net/trafficsqueezer/skbuff.h>
#include <net/trafficsqueezer/memreplace.h>


/* Copyright (c) 2005 Pascal Gloor <pascal.gloor@spale.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * ts_memmem() API is an api derived from memmem() API which is written by Pascal Gloor.
 * to avoid namespace issues in future naming it as "memmem()" it is renamed as ts_memmem().
 */


void *ts_memmem(const void *l, size_t l_len, const void *s, size_t s_len)
{
	register char *cur, *last;
	const char *cl = (const char *)l;
	const char *cs = (const char *)s;

	/* we need something to compare */
	if (l_len == 0 || s_len == 0)
		return NULL;

	/* "s" must be smaller or equal to "l" */
	if (l_len < s_len)
		return NULL;

	/* special case where s_len == 1 */
	if (s_len == 1)
		return memchr(l, (int)*cs, l_len);

	/* the last position where its possible to find "s" in "l" */
	last = (char *)cl + l_len - s_len;

	for (cur = (char *)cl; cur <= last; cur++)
		if (cur[0] == cs[0] && memcmp(cur, cs, s_len) == 0)
			return cur;

	return NULL;
}

static void ts_memleft(BYTE *buf, size_t buflen, size_t shift_count)
{
	int i=0;
	for(i=0;i<buflen;i++)
	{
		*(buf+i) = *(buf+i+shift_count);
	}
}

static void ts_memright(BYTE *buf, size_t buflen, size_t shift_count)
{
	int i=0;
	for(i=(buflen-1);i>=0;i--)
	{
		*(buf+i+shift_count) = *(buf+i);
	}
}

bool ts_memreplace(BYTE *buffer, size_t *buffer_len, BYTE *match_data, size_t match_data_len, BYTE *replace_data, size_t replace_data_len, int skip_key)
{
	BYTE *pos = buffer;
	size_t delta = 0;    //Delta the actual difference between the match_data and the replace_data (which is ALWAYS a positive number)

	while(1)
	{
		//Is this some sort of corrupted packet exceeding buffer limits ?
		if((*buffer_len) >= TS_MAX_OPT_BUF_LEN) return false;

		//Optimization: skip this pos, if it already matches key !!
		///WARNING: should be only be used in non-key optimization replacements !
		if(skip_key==SKIP_KEY) //optimization
		{
			if((*pos)==replace_data[0])
			{
				pos++; //increment pointer (if key) !!
				if(pos >= (buffer+(*buffer_len))) break;
			}
		}
		
		if(match_data_len>1)
		{
			pos = (BYTE *)ts_memmem((BYTE *)pos, (size_t)((*buffer_len)-(size_t)(pos-buffer)), (BYTE *)match_data, (size_t)match_data_len);
		}
		else
		{
			pos = (BYTE *)memchr((BYTE *)pos, (int)match_data[0], (size_t)((*buffer_len)-(size_t)(pos-buffer)));
		}

		//No more replacements?
		if(pos==NULL) break;

		if(pos >= (buffer+(*buffer_len))) break;

		if(replace_data_len==0)  // Remove the match data ?
		{
			delta = (match_data_len-replace_data_len);
			ts_memleft( pos, (size_t)((*buffer_len)-(size_t)(pos-buffer)), delta);
			(*buffer_len) -= delta;
			pos += (replace_data_len);
		}
		else if(match_data_len == replace_data_len) // Just RAW Binary Replace
		{
			memcpy( (BYTE *)pos, (BYTE *)replace_data, (size_t)replace_data_len);
			//delta is 0, hence no buffer_length adjust !!
			pos += (replace_data_len);
		}
		else if(match_data_len > replace_data_len) // Optimization ?
		{
			//First copy since replace is smaller than match data
			memcpy( (BYTE *)pos, (BYTE *)replace_data, (size_t)replace_data_len);
			pos += replace_data_len;
			delta = (match_data_len-replace_data_len);
			ts_memleft( pos, (size_t)((*buffer_len)-(size_t)(pos-buffer)), delta);
			(*buffer_len) -= delta;
		}
		else if(match_data_len < replace_data_len) // Un-Optimization ?
		{
			delta = (replace_data_len-match_data_len);
			ts_memright( pos, (size_t)((*buffer_len)-(size_t)(pos-buffer)), delta);
			memcpy( (BYTE *)pos, (BYTE *)replace_data, (size_t)replace_data_len);
			(*buffer_len) += delta;
			pos += (replace_data_len);
		}
		else
		{
			//Seems some bug ?? Return unconditionally !!
			break;
		}

		if(pos >= (buffer+(*buffer_len))) break;
	}

	return true;
}

//TS memreplace is the core API can be used highly effectively for any raw binary match and replacements
//To test this API here is a sample user-space can be used on any high-priority fix or review/debugging the same !
#if 0

#include <stdio.h>
#include <string.h>
#define TS_TRUE 1
#define TS_FALSE 0
typedef unsigned char BYTE;  

int main()
{
	char source_unmodified[100];
	char source[100];
	memset(source, '\0', 100);
	strcpy(source, "88888This is kiran asfjlwjer welrkj ^|kiran888888888");
	strcpy(source_unmodified, source);
	size_t source_len = 56;
	source[source_len]=0;
	printf("BEFORE: %s\n", source);


	ts_memreplace(source, &source_len, "^", 1, "^|", 2, TS_FALSE); 
	source[source_len]=0;
	printf("AFTER0: %s\n", source);
	ts_memreplace(source, &source_len, "kiran", 5, "^8", 2, TS_TRUE); 
	source[source_len]=0;
	printf("AFTER1: %s   -> \"kiran\", 5, \"^8\", 2\n", source);
	ts_memreplace(source, &source_len, "8888", 4, "^@", 2, TS_TRUE);
	source[source_len]=0;
	printf("AFTER2: %s   -> \"8888\", 4, \"^@\", 2\n", source);
	ts_memreplace(source, &source_len, "^@^@", 4, "~5", 2, TS_TRUE);
	source[source_len]=0;
	printf("AFTER3: %s   -> \"^@^@\", 4, \"~5\", 2\n", source);

	ts_memreplace(source, &source_len, "~5", 2, "^@^@", 4, TS_FALSE); 
	source[source_len]=0;
	printf("AFTER4: %s -> \"~5\", 2, \"^@^@\", 4\n", source);
	ts_memreplace(source, &source_len, "^@", 2, "8888", 4, TS_FALSE); 
	source[source_len]=0;
	printf("AFTER5: %s -> \"^@\", 2, \"8888\", 4\n", source);
	ts_memreplace(source, &source_len, "^8", 2, "kiran", 5, TS_FALSE);
	source[source_len]=0;
	printf("AFTER6: %s -> \"^8\", 2, \"kiran\", 5 \n", source);
	ts_memreplace(source, &source_len, "^|", 2, "^", 1, TS_FALSE);
	source[source_len]=0;
	printf("AFTER7: %s  -> \"^|\", 2, \"^\", 1\n", source);
	printf("UNMODI: %s\n", source_unmodified);

	return TS_TRUE;
}

//Should give output: - for reference !
BEFORE: 88888This is kiran asfjlwjer welrkj ^|kiran888888888
AFTER0: 88888This is kiran asfjlwjer welrkj ^||kiran888888888
AFTER1: 88888This is ^8 asfjlwjer welrkj ^||^8888888888   -> "kiran", 5, "^8", 2
AFTER2: ^@8This is ^8 asfjlwjer welrkj ^||^^@^@88   -> "8888", 4, "^@", 2
AFTER3: ^@8This is ^8 asfjlwjer welrkj ^||^~588   -> "^@^@", 4, "~5", 2
AFTER4: ^@8This is ^8 asfjlwjer welrkj ^||^^@^@88 -> "~5", 2, "^@^@", 4
AFTER5: 88888This is ^8 asfjlwjer welrkj ^||^8888888888 -> "^@", 2, "8888", 4
AFTER6: 88888This is kiran asfjlwjer welrkj ^||kiran888888888 -> "^8", 2, "kiran", 5 
AFTER7: 88888This is kiran asfjlwjer welrkj ^|kiran888888888  -> "^|", 2, "^", 1
UNMODI: 88888This is kiran asfjlwjer welrkj ^|kiran888888888
#endif