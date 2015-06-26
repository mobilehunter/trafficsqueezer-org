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
#include <net/protocol.h>
#include <linux/ctype.h>
#include <linux/gfp.h>
#include <linux/lzo.h>
#include <linux/lz4.h>
#include <net/trafficsqueezer/core.h>
#include <net/trafficsqueezer/proc.h>
#include <net/trafficsqueezer/init.h>
#include <net/trafficsqueezer/dpi_core.h>
#include <net/trafficsqueezer/dpi_dns.h>
#include <net/trafficsqueezer/dpi_pop.h>
#include <net/trafficsqueezer/dpi_http.h>
#include <net/trafficsqueezer/filter_dns.h>
#include <net/trafficsqueezer/coal.h>
#include <net/trafficsqueezer/stats.h>
#include <net/trafficsqueezer/templ.h>

static void init_ts_templ_generic(void);
static void init_ts_templ_common(void);
static void init_ts_templ_http(void);
static void init_ts_templ_dns(void);
static void init_ts_templ_telnet(void);
static void init_ts_templ_imap(void);
static void init_ts_templ_mapi(void);
static void init_ts_templ_ftp(void);
static void init_ts_templ_nfs(void);
static void init_ts_templ_mysql(void);
static void init_ts_templ_pgsql(void);
static void init_ts_templ_sql(void);
static void init_ts_templ_mssql(void);
static void init_ts_templ_ssh(void);
static void init_ts_templ_ssl(void);
static void init_ts_templ_pop(void);
static void init_ts_templ_smtp(void);
static void init_ts_templ_ica(void);
static void init_ts_templ_rdp(void);
static void init_ts_templ_spice(void);
static void init_ts_templ_voip(void);
static void init_ts_templ_sip(void);
static void init_ts_templ_h323(void);
static void init_ts_templ_ldap(void);
static void init_ts_templ_krb(void);
static void init_ts_templ_smb(void);
static void init_ts_templ_ssdp(void);
static void init_ts_http_templ_dict(void);

static void avoid_key(BYTE *k)
{	while((*k)=='^' || (*k)=='~' || (*k)==0x01 || (*k)==0x07 || (*k)==0x08) { (*k)++; } }

static void ts_add_str_templ_common_tag(ts_dict_t *dict, char tag, int tag_len, BYTE pk, BYTE *k, int *count)
{ if(dict==NULL) return;
  avoid_key(k); dict->k[0]=pk; dict->k[1]=(*k); (*k)++; (*count)++;
  memset(dict->txt, tag, tag_len); dict->txt_len=tag_len;
}

static void ts_add_str_templ_tag(ts_dict_t *dict, char *tag, BYTE pk, BYTE *k, int *count)
{ if(dict==NULL) return;
  avoid_key(k); dict->k[0]=pk; dict->k[1]=(*k); (*k)++; (*count)++;
  strcpy(dict->txt, tag); dict->txt_len=(strlen(tag));
}

static void ts_add_bnry_templ_tag(ts_dict_t *dict, char *binary_tag, int binary_tag_len, BYTE pk, BYTE *k, int *count)
{ if(dict==NULL) return;
  avoid_key(k); dict->k[0]=pk; dict->k[1]=(*k); (*k)++; (*count)++;
  memcpy(dict->txt, binary_tag, binary_tag_len); dict->txt_len=binary_tag_len;
}

void init_ts_templ_generic()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk=0x07;
	int i=0;

//Application (generic files, documents)
//PDF ?
   ts_add_str_templ_tag(&ts_templ_generic[i], "<</Type/XObject/Subtype/Image/Width",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/Filter/FlateDecode/ColorSpace/DeviceRGB",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/ColorSpace/DeviceRGB/Filter/DCTDecode/Length",  0x07, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/BitsPerComponent",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/FlateDecode",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/FontDescriptor",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/Filter/FlateDecode>>",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "<</Length ",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/Length",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/ItalicAngle",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "endstream",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "stream",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/CreationDate",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/ModDate",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/Creator",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/Producer",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/DefaultCMYK",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/ColorSpace",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/BitsPerComponent",  pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "Adobe Photoshop ",  pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "/CCITTFaxDecode",  pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "/Properties",  pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "/Contents",  pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "/DeviceGray",  pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "/Linearized",  pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "/ExtGState",  pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "/DecodeParms",  pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "/Resources",  pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " obj",  pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "endobj",  pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "/XObject",  pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "/Rotate",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/Title",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/Type",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "/Page",  pk, &k, &i);
 
//MS Doc ?
   ts_add_str_templ_tag(&ts_templ_generic[i], "HYPERLINK ",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "Microsoft ",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "Document",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "MSWordDoc",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "Word",  pk, &k, &i);

//MS Excel ?
   ts_add_str_templ_tag(&ts_templ_generic[i], "Microsoft Excel ",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "GENERAL",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "PORTRAIT ",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "Sheet",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "Page",  pk, &k, &i);

//MS PPT ?
   ts_add_str_templ_tag(&ts_templ_generic[i], "MS PowerPoint ",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "PowerPoint",  pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], "Current User",  pk, &k, &i);

//PNG
  	ts_add_str_templ_tag(&ts_templ_generic[i], "PNG", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "IDATx", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "tIME", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "sRGB", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "IEND", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "sBIT", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "pHYs", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "tEXtTitle", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "tEXtSoftware", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "tEXtComment", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "zTXtDescription", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "tEXtAuthor", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "Unknown", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "tEXt", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "bKGD", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "tRNS", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "zTXt", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "gAMA", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "cHRM", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "IDATh", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "Created with The GIMP", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "Created with GIMPW", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "Adobe ImageReady", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "www.inkscape.org", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "Made with Sodipodi", pk, &k, &i);
  	
//GIF
  	ts_add_str_templ_tag(&ts_templ_generic[i], "GIF89a", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "GIF87a", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "GIF", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "NETSCAPE2", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "NETSCAPE", pk, &k, &i);
  	
//JPEG
  	ts_add_str_templ_tag(&ts_templ_generic[i], "JFIF", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "CREATOR: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "89:CDEFGHIJSTUVWXYZcdefghijstuvwxyz", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "quality", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "JPEG", pk, &k, &i);
	
//Country/Place/Town/Village Names
	ts_add_str_templ_tag(&ts_templ_generic[i], "nited", pk, &k, &i); //US, UAE, UK, also domains, pages, ....
	ts_add_str_templ_tag(&ts_templ_generic[i], "ndia", pk, &k, &i); // also domains, pages, ....
	ts_add_str_templ_tag(&ts_templ_generic[i], "New ", pk, &k, &i); //New Delhi, New Zealand, New York ....
	ts_add_str_templ_tag(&ts_templ_generic[i], "merica", pk, &k, &i);  //also domains, pages, ....
	ts_add_str_templ_tag(&ts_templ_generic[i], "taly", pk, &k, &i); // also domains, pages, ....
	ts_add_str_templ_tag(&ts_templ_generic[i], "ndonesia", pk, &k, &i); // also domains, pages, ....
	ts_add_str_templ_tag(&ts_templ_generic[i], "hina", pk, &k, &i); // also domains, pages, ....
	ts_add_str_templ_tag(&ts_templ_generic[i], "ustralia", pk, &k, &i); // also domains, pages, ....
	ts_add_str_templ_tag(&ts_templ_generic[i], "land", pk, &k, &i); // greenland, ice-land, england, land, ...

//Normal text and English grammar
	ts_add_str_templ_tag(&ts_templ_generic[i], " that ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " their ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "The ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "Where ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "When ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " the ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " was ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " but ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " are ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "And ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " and ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " an ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " about ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " is ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " it ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " its ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " on ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " as ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " or ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " be ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " to ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " this ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " with ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " without ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " were ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " which ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " would ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " very ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " your ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " from ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " for ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " had ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " having ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " should ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " getting ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " according ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " have ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " has ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " his ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " her ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " not ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " he ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " she ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " will ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " called ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], " after ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "because", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "between", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "something", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "people", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "whatever", pk, &k, &i);
	
//Partial words strings
	ts_add_str_templ_tag(&ts_templ_generic[i], "overnment", pk, &k, &i); //Government
	ts_add_str_templ_tag(&ts_templ_generic[i], "mportant", pk, &k, &i); //Important
	ts_add_str_templ_tag(&ts_templ_generic[i], "nformation", pk, &k, &i); //Information
	ts_add_str_templ_tag(&ts_templ_generic[i], "emperature", pk, &k, &i); //Temperature
	ts_add_str_templ_tag(&ts_templ_generic[i], "nderstand", pk, &k, &i); //Understand, Understanding ...

///////Month names
	ts_add_str_templ_tag(&ts_templ_generic[i], "anuary", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "ebruary", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "arch", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "pril", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "ugust", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "eptember", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "ctober", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "ovember", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "ecember", pk, &k, &i);	

//IMPORTANT Keyword - Javascripts, HTML, normal text, or any files
  	ts_add_str_templ_tag(&ts_templ_generic[i], "this", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "else", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_generic[i], "mail", pk, &k, &i);

//Domain Names, sub domains, file/folder paths
	ts_add_str_templ_tag(&ts_templ_generic[i], ".com>", pk, &k, &i); //Emails/HTML/Documents/TXT
	ts_add_str_templ_tag(&ts_templ_generic[i], ".com", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], ".co.uk", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], ".co.us", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], ".co.in", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], ".co.jp", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], ".co.it", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], ".net", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], ".org", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "movies", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "mobile", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "solution", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "music", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "game", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "astro", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "news", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "finance", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "download", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "search", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "photo", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "gallery", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "article", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "market", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "stock", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "technology", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "tech", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "shopping", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "entertainment", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "forum", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "script", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "jobs", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "shop", pk, &k, &i); //ecommerce, ebay, shopping, ....
	ts_add_str_templ_tag(&ts_templ_generic[i], "file", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "feed", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "submit", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "share", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "apps", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "slide", pk, &k, &i); //slides/slideshow
	ts_add_str_templ_tag(&ts_templ_generic[i], "static", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "comment", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "health", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "weather", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "business", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "travel", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "data", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "world", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "default", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "sport", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "international", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "logo", pk, &k, &i); //logos, logo_XXX.png, jpg,...,logos/ 

//Filenames
   ts_add_str_templ_tag(&ts_templ_generic[i], ".html", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".htm", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".xml", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".txt", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".jpeg", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".jpg", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".png", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".gif", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".css", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".php", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".pdf", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".doc", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".ppt", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".asp", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".swf", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".zip", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".tar.gz", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_generic[i], ".tar.bz2", pk, &k, &i);	

//Partial English grammar
	ts_add_str_templ_tag(&ts_templ_generic[i], "thing ", pk, &k, &i); //something, nothing, everything, ....
	ts_add_str_templ_tag(&ts_templ_generic[i], "thing", pk, &k, &i); //something, nothing, everything, ....
	ts_add_str_templ_tag(&ts_templ_generic[i], "aed ", pk, &k, &i); //instead, subpoenaed, ...
	ts_add_str_templ_tag(&ts_templ_generic[i], "ness ", pk, &k, &i); //Plural
	ts_add_str_templ_tag(&ts_templ_generic[i], "ess ", pk, &k, &i); //Plural
	ts_add_str_templ_tag(&ts_templ_generic[i], "ses ", pk, &k, &i); //Plural
	ts_add_str_templ_tag(&ts_templ_generic[i], "tive ", pk, &k, &i); // positive, negative, initiative, conservative ...
	ts_add_str_templ_tag(&ts_templ_generic[i], "tions ", pk, &k, &i); //Verb: actions, modifications, clarifications, ...
	ts_add_str_templ_tag(&ts_templ_generic[i], "tion ", pk, &k, &i); //information, caution, attention, nation....
	ts_add_str_templ_tag(&ts_templ_generic[i], "ion ", pk, &k, &i); // phenominon, anion, polyhedron
	ts_add_str_templ_tag(&ts_templ_generic[i], "ium ", pk, &k, &i); // forum, medium, millennium
	ts_add_str_templ_tag(&ts_templ_generic[i], "ful ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "full ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "fully ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "fully", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "full", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_generic[i], "ally ", pk, &k, &i); // fundamentally, ...
	ts_add_str_templ_tag(&ts_templ_generic[i], "ity ", pk, &k, &i); // security, maturity
	ts_add_str_templ_tag(&ts_templ_generic[i], "ify ", pk, &k, &i); //Verb: modify, beautify, magnify, clarify  
	ts_add_str_templ_tag(&ts_templ_generic[i], "ology ", pk, &k, &i); //Noun: biology, zoology, technology, archeology, astrology
	ts_add_str_templ_tag(&ts_templ_generic[i], "way ", pk, &k, &i); // highway, gateway, freeway
	ts_add_str_templ_tag(&ts_templ_generic[i], "work ", pk, &k, &i); // social-work, homework, network, framework,..

	ts_templ_generic_count = i;
} /* init_ts_templ_generic */

void init_ts_templ_common()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk=0x08;
	int i=0, j=0;
	char binary_tag[60]; memset(binary_tag, 0x00, 60);

 	for(j=20;j>=3;j--)
	{	
		ts_add_str_templ_common_tag(&ts_templ_common[i], ' ', j, pk, &k, &i);
		ts_add_str_templ_common_tag(&ts_templ_common[i], 0x00, j, pk, &k, &i);
		ts_add_str_templ_common_tag(&ts_templ_common[i], 0xff, j, pk, &k, &i);
		if(j<=8 && j>=3)
		{
			ts_add_str_templ_common_tag(&ts_templ_common[i], '0', j, pk, &k, &i);
			ts_add_str_templ_common_tag(&ts_templ_common[i], '-', j, pk, &k, &i);
			ts_add_str_templ_common_tag(&ts_templ_common[i], '=', j, pk, &k, &i);
			ts_add_str_templ_common_tag(&ts_templ_common[i], '\n', j, pk, &k, &i);
			ts_add_str_templ_common_tag(&ts_templ_common[i], '\t', j, pk, &k, &i);
		} 
	}

//UDP Header [Port DNS][1st Byte Len 0x00]
	binary_tag[0]=0x00; binary_tag[1]=0x35; binary_tag[2]=0x00;
	ts_add_bnry_templ_tag(&ts_templ_common[i], binary_tag, 3, pk, &k, &i);

//TCP Header 0x00 0x00 0x01 0x01 (After checksum 0x00 0x00 and options header start 0x01 0x01)
	binary_tag[0]=0x00; binary_tag[1]=0x00; binary_tag[2]=0x01; binary_tag[3]=0x01;
	ts_add_bnry_templ_tag(&ts_templ_common[i], binary_tag, 4, pk, &k, &i);

//TCP Header HDR-LEN|ACK|Window start 0x00, 0x01, 0x00
	binary_tag[0]=0x80; binary_tag[1]=0x10; binary_tag[2]=0x00;
	ts_add_bnry_templ_tag(&ts_templ_common[i], binary_tag, 3, pk, &k, &i);
	binary_tag[2]=0x01;
	ts_add_bnry_templ_tag(&ts_templ_common[i], binary_tag, 3, pk, &k, &i);
	binary_tag[2]=0x02;
	ts_add_bnry_templ_tag(&ts_templ_common[i], binary_tag, 3, pk, &k, &i); 

//TCP Header HDR-LEN|PSH-ACK|Window start 0x00
	binary_tag[0]=0x80; binary_tag[1]=0x18; binary_tag[2]=0x00;
	ts_add_bnry_templ_tag(&ts_templ_common[i], binary_tag, 3, pk, &k, &i);

//TCP Header HDR-LEN|RST|Window start 0x00 & 0x00 0x00
	binary_tag[0]=0x50; binary_tag[1]=0x04; binary_tag[2]=0x00; binary_tag[3]=0x00;
	ts_add_bnry_templ_tag(&ts_templ_common[i], binary_tag, 4, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_common[i], binary_tag, 3, pk, &k, &i);
	
//ICMP Packets
	ts_add_str_templ_tag(&ts_templ_common[i], "ABCDEFGHIJKLMNOPQRSTUVWXYZ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "01234567", pk, &k, &i);

//Current Year - occurs in generic text, HTTP expiry dates, email dates, etc etc.
	ts_add_str_templ_tag(&ts_templ_common[i], " 2014", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "2014 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "2014", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], " 2013", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "2013 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "2013", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], " 2012", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "2012 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "2012", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "198", pk, &k, &i); //year, http, ftp, emails, files, DOB
	ts_add_str_templ_tag(&ts_templ_common[i], "199", pk, &k, &i); //year, http, ftp, emails, files, DOB
	ts_add_str_templ_tag(&ts_templ_common[i], "200", pk, &k, &i); //HTTP Reply, year, etc etc.
	ts_add_str_templ_tag(&ts_templ_common[i], "201", pk, &k, &i); //Year and future year such as expiry date - year, http, ftp, emails, files, DOB

//Numbers - Generic Dates etc etc - FTP/HTTP/Emails, DB or any files in general.
	ts_add_str_templ_tag(&ts_templ_common[i], "00 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "01 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "02 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "03 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "04 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "05 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "06 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "07 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "08 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "09 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "10 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "11 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "12 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "13 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "14 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "15 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "16 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "17 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "18 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "19 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "20 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "21 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "22 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "23 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "24 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "25 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "26 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "27 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "28 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "29 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "30 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "31 ", pk, &k, &i);
	
//PNG (no space in generic, so adding in common)
	ts_add_str_templ_tag(&ts_templ_common[i], "CreatorTool=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "Description", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "xpacket", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "documentID=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "begin=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "about=", pk, &k, &i);
	
//OCSP (HTTP Tags)
	ts_add_str_templ_tag(&ts_templ_common[i], "POST /ocsp HTTP/1.1\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "Content-Type: application/ocsp-request\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "Content-Type: application/ocsp-response\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_common[i], "HTTP/1.1 301 Moved Permanently\r\n", pk, &k, &i);

//STUN (VOIP) control packets
	//Binding Request (within it Magic Cookie)
	binary_tag[0]=0x00; binary_tag[1]=0x01; binary_tag[2]=0x00; binary_tag[3]=0x08;
	binary_tag[4]=0x21; binary_tag[5]=0x12; binary_tag[6]=0xa4; binary_tag[7]=0x42; //Magic Cookie
	ts_add_bnry_templ_tag(&ts_templ_common[i], binary_tag, 8, pk, &k, &i);

	//Magic Cookie alone (for responses, failure and other kind of STUN packets)
	binary_tag[0]=0x21; binary_tag[1]=0x12; binary_tag[2]=0xa4; binary_tag[3]=0x42; //Magic Cookie
	ts_add_bnry_templ_tag(&ts_templ_common[i], binary_tag, 4, pk, &k, &i);

	
//other misc common words may exist in all protocol packets
 ts_add_str_templ_tag(&ts_templ_common[i], "children", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "child", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "every", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "still", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "return", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "therefore", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "distributed", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "follow", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "these", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "inherit", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "great", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "toward", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "lead", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "multi", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "against", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "again", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], " shall ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "women", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "God ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "God", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "akamai", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "thou", pk, &k, &i); //thou, without, thousand...
 ts_add_str_templ_tag(&ts_templ_common[i], "android", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Android", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "microsoft", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Microsoft", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "windows", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Windows", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "command", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "money", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "time", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "generation", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "hundred", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "thousand", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "million", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "billion", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "dollar", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "month", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "year", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Apple", pk, &k, &i);
 
//Zodiac sign names
 ts_add_str_templ_tag(&ts_templ_common[i], "aries", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Aries", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "taurus", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Taurus", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "gemini", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Gemini", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "cancer", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Cancer", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "leo", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Leo", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "virgo", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Virgo", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "libra", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Libra", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "scorpio", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Scorpio", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "sagittarius", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Sagittarius", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "capricorn", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Capricorn", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "aquarius", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Aquarius", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "pisces", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Pisces", pk, &k, &i);
 
//Software source code
 ts_add_str_templ_tag(&ts_templ_common[i], "Copyright", pk, &k, &i); 
 ts_add_str_templ_tag(&ts_templ_common[i], "software", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "source", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "#include", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "void", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "char", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "break", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "struct", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "linux", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "print", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "unsigned", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "strlen", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "switch", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "isom3gp4", pk, &k, &i);
 
//Common Page Text
 ts_add_str_templ_tag(&ts_templ_common[i], "Contact", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "contact", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "About", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "about", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "info", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "career", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "sitemap", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Home", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "mailto:", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "Password", pk, &k, &i); //password - already added
 ts_add_str_templ_tag(&ts_templ_common[i], "login", pk, &k, &i); //password - already added

//Grammer
 ts_add_str_templ_tag(&ts_templ_common[i], "tal ", pk, &k, &i); // general, fundamental, supplimental	
 ts_add_str_templ_tag(&ts_templ_common[i], "ing ", pk, &k, &i); //tenses
 ts_add_str_templ_tag(&ts_templ_common[i], "n't ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_common[i], "ant ", pk, &k, &i); // constant, important, ...

 ts_templ_common_count = i;
} /* init_ts_templ_common */

void init_ts_templ_http()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk='~';
	int i=0; 

	ts_add_str_templ_tag(&ts_templ_http[i], "text/css", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "text/javascript", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "background-color", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "javascript", pk, &k, &i);
        
//Tagspk
  ts_add_str_templ_tag(&ts_templ_http[i], "<html><head>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<html>\n<head>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</body></html>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</body>\n</html>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<body ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<body>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</body>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<BODY>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</BODY>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<html>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<HTML>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</HTML>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</html>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<head>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</head>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<meta ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<title>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</title>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<script ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</script>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</b>", pk, &k, &i);
  
  ts_add_str_templ_tag(&ts_templ_http[i], "<a href=\"", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<img src=\"", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<img ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<embed src=\"", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<embed ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</a>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<br>\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<br><br>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<br/>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<br>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<hr>\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<hr>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<hr ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<span ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</span>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<div ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</div>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<font ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</font>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<li ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</li>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<table ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</table>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<td></td>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<td ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<td>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</td>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<tr ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<tr>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</tr>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<textarea ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</textarea>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<input ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<iframe ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<select ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "</select>", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "<option ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " />", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " >\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "\">\n", pk, &k, &i);
  
//CSS/HTML
	ts_add_str_templ_tag(&ts_templ_http[i], "0px;", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "1px;", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "2px;", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "3px;", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "4px;", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "5px;", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "6px;", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "7px;", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "8px;", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "9px;", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "px;", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "px;\"", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "px\"", pk, &k, &i);

//Special characters
   ts_add_str_templ_tag(&ts_templ_http[i], "&nbsp;&nbsp;", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_http[i], "&nbsp;", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_http[i], "&copy;", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_http[i], "&amp;", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_http[i], "&lt;", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_http[i], "&gt;", pk, &k, &i);
   
//HTML Comment
   ts_add_str_templ_tag(&ts_templ_http[i], "<!--", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_http[i], "-->", pk, &k, &i);
   
//Scripts
   ts_add_str_templ_tag(&ts_templ_http[i], "NULL", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_http[i], "null", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_http[i], ");\n", pk, &k, &i);

        
//Events        
  ts_add_str_templ_tag(&ts_templ_http[i], "onmousedown", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "mousedown", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "onmousemove", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "onmouseout", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "onmouseup", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "ondblclick", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "onchange", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "onload", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "onsubmit", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "onfocus", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "onclick", pk, &k, &i);
  
  ts_add_str_templ_tag(&ts_templ_http[i], "alert", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "function", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "none", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "var ", pk, &k, &i); //javascript variable declaration
  
  ts_add_str_templ_tag(&ts_templ_http[i], "document.getElementById", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "getElementById", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "getElementByName", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "getElementsByClass", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "addEventListener", pk, &k, &i);
    
  ts_add_str_templ_tag(&ts_templ_http[i], "document", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "write", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "background", pk, &k, &i);
  
  ts_add_str_templ_tag(&ts_templ_http[i], "cellspacing=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "cellpadding=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "border", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "margin", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "content", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "position:relative;", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "position:absolute;", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "http-equiv=\"Content-Type\"", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "favicon.ico", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "icon", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "theme", pk, &k, &i);

//Small letter tags  
  ts_add_str_templ_tag(&ts_templ_http[i], "server: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "keep-alive: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "last-modified: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "content-type: ", pk, &k, &i);

  ts_add_str_templ_tag(&ts_templ_http[i], "width", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "height", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "center", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "left", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "right", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "password", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "readonly", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "selected", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "disabled", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "align", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "padding", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "opacity", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "\"_blank\"", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "_blank", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "solid", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "button", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "arial", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "visibility", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "hover", pk, &k, &i);

  ts_add_str_templ_tag(&ts_templ_http[i], "font-family", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "font-weight", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "display", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "font-size", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "text-decoration", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " style=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "style=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " href=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "href=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " type=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " src=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "src=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " alt=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " rel=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " method=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " action=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " value=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " name=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " class=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "class=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " id=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "id=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " userid=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "userid=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " bgcolor=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " target=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], " title=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "_blank", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "hidden", pk, &k, &i);
  
  ts_add_str_templ_tag(&ts_templ_http[i], "http://www.", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "http://", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "http", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "https://www.", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "https://", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "ftp://www.", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "ftp://", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "www.", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "www", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "index.", pk, &k, &i); //index.html, index.php, index.htm, etc
  ts_add_str_templ_tag(&ts_templ_http[i], "must-revalidate", pk, &k, &i);
  
//Some HTTP Header (not done in http-opt)
  ts_add_str_templ_tag(&ts_templ_http[i], "Accept-Encoding\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "max-age=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "Alternate-Protocol: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "Timing-Allow-Origin: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "x-amz-request-id: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "X-CDN: Served by Akamai\r\n", pk, &k, &i);
      
  //Colors
  ts_add_str_templ_tag(&ts_templ_http[i], "color", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "black", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "#000000", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_http[i], "#ffffff", pk, &k, &i);  
  

//Domains which can be only HTTP !        
	ts_add_str_templ_tag(&ts_templ_http[i], "facebook", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "google", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "youtube", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_http[i], "fedora", pk, &k, &i);

	ts_templ_http_count = i;
} /* init_ts_templ_http */

void init_ts_templ_dns()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk='~';
	int i=0;
	char binary_tag[60]; memset(binary_tag, 0x00, 60);

//Partial or complete website names
	binary_tag[0]=3; //www.google.com
	binary_tag[1]='w'; binary_tag[2]='w'; binary_tag[3]='w';
	binary_tag[4]=6;
	binary_tag[5]='g'; binary_tag[6]='o'; binary_tag[7]='o'; binary_tag[8]='g'; binary_tag[9]='l'; binary_tag[10]='e';
	binary_tag[11]=3;
	binary_tag[12]='c'; binary_tag[13]='o'; binary_tag[14]='m';
	binary_tag[15]=0x00; //ends with 0x00
	binary_tag[16]=0x00; binary_tag[17]=0x01; binary_tag[18]=0x00; binary_tag[19]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 20, pk, &k, &i); //www.google.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 16, pk, &k, &i); //www.google.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+4), 16, pk, &k, &i); //google.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+4), 12, pk, &k, &i); //google.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+4), 7, pk, &k, &i); //google
	//google (word anywhere) -- defined below further

	binary_tag[0]=6; //amazon.com
	binary_tag[1]='a'; binary_tag[2]='m'; binary_tag[3]='a'; binary_tag[4]='z'; binary_tag[5]='o'; binary_tag[6]='n';
	binary_tag[7]=3;
	binary_tag[8]='c'; binary_tag[9]='o'; binary_tag[10]='m';
	binary_tag[11]=0x00; //ends with 0x00
	binary_tag[12]=0x00; binary_tag[13]=0x01; binary_tag[14]=0x00; binary_tag[15]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 16, pk, &k, &i); //amazon.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 12, pk, &k, &i); //amazon.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 7, pk, &k, &i); //amazon
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 6, pk, &k, &i); //amazon (word anywhere)	
	
	binary_tag[0]=4; //plus.
	binary_tag[1]='p'; binary_tag[2]='l'; binary_tag[3]='u';  binary_tag[4]='s';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 5, pk, &k, &i);

	binary_tag[0]=7; //youtube.com
	binary_tag[1]='y'; binary_tag[2]='o'; binary_tag[3]='u'; binary_tag[4]='t'; binary_tag[5]='u'; binary_tag[6]='b'; binary_tag[7]='e';
	binary_tag[8]=3;
	binary_tag[9]='c'; binary_tag[10]='o'; binary_tag[11]='m';
	binary_tag[12]=0x00; //ends with 0x00
	binary_tag[13]=0x00; binary_tag[14]=0x01; binary_tag[15]=0x00; binary_tag[16]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 17, pk, &k, &i); //youtube.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 13, pk, &k, &i); //youtube.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i); //youtube
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 7, pk, &k, &i); //youtube (word anywhere)
	
	
	binary_tag[0]=8; //facebook.com
	binary_tag[1]='f'; binary_tag[2]='a'; binary_tag[3]='c'; binary_tag[4]='e'; binary_tag[5]='b'; binary_tag[6]='o'; binary_tag[7]='o'; binary_tag[8]='k';
	binary_tag[9]=3;
	binary_tag[10]='c'; binary_tag[11]='o'; binary_tag[12]='m';
	binary_tag[13]=0x00; //ends with 0x00
	binary_tag[14]=0x00; binary_tag[15]=0x01; binary_tag[16]=0x00; binary_tag[17]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 18, pk, &k, &i); //facebook.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 14, pk, &k, &i); //facebook.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 9, pk, &k, &i); //facebook
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 8, pk, &k, &i); //facebook (word anywhere)
	
	binary_tag[0]=8; //vimeocdn.com
	binary_tag[1]='v'; binary_tag[2]='i'; binary_tag[3]='m'; binary_tag[4]='e'; binary_tag[5]='o'; binary_tag[6]='c'; binary_tag[7]='d'; binary_tag[8]='n';
	binary_tag[9]=3;
	binary_tag[10]='c'; binary_tag[11]='o'; binary_tag[12]='m';
	binary_tag[13]=0x00; //ends with 0x00
	binary_tag[14]=0x00; binary_tag[15]=0x01; binary_tag[16]=0x00; binary_tag[17]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 18, pk, &k, &i); //vimeocdn.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 14, pk, &k, &i); //vimeocdn.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 9, pk, &k, &i); //vimeocdn
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 8, pk, &k, &i); //vimeocdn (word anywhere)
	
	binary_tag[0]=8; //linkedin.com
	binary_tag[1]='l'; binary_tag[2]='i'; binary_tag[3]='n'; binary_tag[4]='k'; binary_tag[5]='e'; binary_tag[6]='d'; binary_tag[7]='i'; binary_tag[8]='n';
	binary_tag[9]=3;
	binary_tag[10]='c'; binary_tag[11]='o'; binary_tag[12]='m';
	binary_tag[13]=0x00; //ends with 0x00
	binary_tag[14]=0x00; binary_tag[15]=0x01; binary_tag[16]=0x00; binary_tag[17]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 18, pk, &k, &i); //linkedin.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 14, pk, &k, &i); //linkedin.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 9, pk, &k, &i); //linkedin
	
	
	binary_tag[0]=7; //twitter.com
	binary_tag[1]='t'; binary_tag[2]='w'; binary_tag[3]='i'; binary_tag[4]='t'; binary_tag[5]='t'; binary_tag[6]='e'; binary_tag[7]='r';
	binary_tag[8]=3;
	binary_tag[9]='c'; binary_tag[10]='o'; binary_tag[11]='m';
	binary_tag[12]=0x00; //ends with 0x00
	binary_tag[13]=0x00; binary_tag[14]=0x01; binary_tag[15]=0x00; binary_tag[16]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 17, pk, &k, &i); //twitter.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 13, pk, &k, &i); //twitter.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i); //twitter
	
	binary_tag[0]=7; //godaddy.com
	binary_tag[1]='g'; binary_tag[2]='o'; binary_tag[3]='d'; binary_tag[4]='a'; binary_tag[5]='d'; binary_tag[6]='d'; binary_tag[7]='y';
	binary_tag[8]=3;
	binary_tag[9]='c'; binary_tag[10]='o'; binary_tag[11]='m';
	binary_tag[12]=0x00; //ends with 0x00
	binary_tag[13]=0x00; binary_tag[14]=0x01; binary_tag[15]=0x00; binary_tag[16]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 17, pk, &k, &i); //godaddy.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 13, pk, &k, &i); //godaddy.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i); //godaddy
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 7, pk, &k, &i); //godaddy (word anywhere)
	
	binary_tag[0]=7; //blogger.com
	binary_tag[1]='b'; binary_tag[2]='l'; binary_tag[3]='o'; binary_tag[4]='g'; binary_tag[5]='g'; binary_tag[6]='e'; binary_tag[7]='r';
	binary_tag[8]=3;
	binary_tag[9]='c'; binary_tag[10]='o'; binary_tag[11]='m';
	binary_tag[12]=0x00; //ends with 0x00
	binary_tag[13]=0x00; binary_tag[14]=0x01; binary_tag[15]=0x00; binary_tag[16]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 17, pk, &k, &i); //blogger.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 13, pk, &k, &i); //blogger.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i); //blogger
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 7, pk, &k, &i); //blogger (word anywhere)
	
	binary_tag[0]=5; //yahoo.com
	binary_tag[1]='y'; binary_tag[2]='a'; binary_tag[3]='h'; binary_tag[4]='o'; binary_tag[5]='o';
	binary_tag[6]=3;
	binary_tag[7]='c'; binary_tag[8]='o'; binary_tag[9]='m';
	binary_tag[10]=0x00; //ends with 0x00
	binary_tag[11]=0x00; binary_tag[12]=0x01; binary_tag[13]=0x00; binary_tag[14]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 15, pk, &k, &i); //yahoo.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 11, pk, &k, &i); //yahoo.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 6, pk, &k, &i); //yahoo
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 5, pk, &k, &i); //yahoo (word anywhere)
	
	binary_tag[0]=9; //wordpress.com
	binary_tag[1]='w'; binary_tag[2]='o'; binary_tag[3]='r'; binary_tag[4]='d'; binary_tag[5]='p';
	binary_tag[6]='r'; binary_tag[7]='e'; binary_tag[8]='s'; binary_tag[9]='s';
	binary_tag[10]=3;
	binary_tag[11]='c'; binary_tag[12]='o'; binary_tag[13]='m';
	binary_tag[14]=0x00; //ends with 0x00
	binary_tag[15]=0x00; binary_tag[16]=0x01; binary_tag[17]=0x00; binary_tag[18]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 19, pk, &k, &i); //wordpress.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 15, pk, &k, &i); //wordpress.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 10, pk, &k, &i); //wordpress
	
	binary_tag[0]=9; //wikipedia.org
	binary_tag[1]='w'; binary_tag[2]='i'; binary_tag[3]='k'; binary_tag[4]='i'; binary_tag[5]='p';
	binary_tag[6]='e'; binary_tag[7]='d'; binary_tag[8]='i'; binary_tag[9]='a';
	binary_tag[10]=3;
	binary_tag[11]='o'; binary_tag[12]='r'; binary_tag[13]='g';
	binary_tag[14]=0x00; //ends with 0x00
	binary_tag[15]=0x00; binary_tag[16]=0x01; binary_tag[17]=0x00; binary_tag[18]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 19, pk, &k, &i); //wordpress.org
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 15, pk, &k, &i); //wordpress.org
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 10, pk, &k, &i); //wordpress

	binary_tag[0]=4; //bing.com
	binary_tag[1]='b'; binary_tag[2]='i'; binary_tag[3]='n'; binary_tag[4]='g';
	binary_tag[5]=3;
	binary_tag[6]='c'; binary_tag[7]='o'; binary_tag[8]='m';
	binary_tag[9]=0x00; //ends with 0x00
	binary_tag[10]=0x00; binary_tag[11]=0x01; binary_tag[12]=0x00; binary_tag[13]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 14, pk, &k, &i); //bing.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 10, pk, &k, &i); //bing.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 5, pk, &k, &i); //bing
	
	binary_tag[0]=4; //ebay.com
	binary_tag[1]='e'; binary_tag[2]='b'; binary_tag[3]='a'; binary_tag[4]='y';
	binary_tag[5]=3;
	binary_tag[6]='c'; binary_tag[7]='o'; binary_tag[8]='m';
	binary_tag[9]=0x00; //ends with 0x00
	binary_tag[10]=0x00; binary_tag[11]=0x01; binary_tag[12]=0x00; binary_tag[13]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 14, pk, &k, &i); //ebay.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 10, pk, &k, &i); //ebay.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 5, pk, &k, &i); //ebay
	
	binary_tag[0]=3; //ask.com
	binary_tag[1]='a'; binary_tag[2]='s'; binary_tag[3]='k';
	binary_tag[4]=3;
	binary_tag[5]='c'; binary_tag[6]='o'; binary_tag[7]='m';
	binary_tag[8]=0x00; //ends with 0x00
	binary_tag[9]=0x00; binary_tag[10]=0x01; binary_tag[11]=0x00; binary_tag[12]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 13, pk, &k, &i); //ask.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 9, pk, &k, &i); //ask.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i); //ask
	
	binary_tag[0]=8; //ISP: etisalat.ae Dubai
	binary_tag[1]='e'; binary_tag[2]='t'; binary_tag[3]='i'; binary_tag[4]='s'; binary_tag[5]='a'; binary_tag[6]='l'; binary_tag[7]='a'; binary_tag[8]='t';
	binary_tag[9]=2;
	binary_tag[10]='a'; binary_tag[11]='e';
	binary_tag[12]=0x00; //ends with 0x00
	binary_tag[13]=0x00; binary_tag[14]=0x01; binary_tag[15]=0x00; binary_tag[16]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 17, pk, &k, &i); //etisalat.ae
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 11, pk, &k, &i); //etisalat.ae
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 9, pk, &k, &i); //etisalat
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 8, pk, &k, &i); //etisalat (word anywhere) 
	
	binary_tag[0]=4; //ISP: bell.ca Canada
	binary_tag[1]='b'; binary_tag[2]='e'; binary_tag[3]='l'; binary_tag[4]='l';
	binary_tag[5]=2;
	binary_tag[6]='c'; binary_tag[7]='a';
	binary_tag[8]=0x00; //ends with 0x00
	binary_tag[9]=0x00; binary_tag[10]=0x01; binary_tag[11]=0x00; binary_tag[12]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 13, pk, &k, &i); //bell.ca
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 9, pk, &k, &i); //bell.ca
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 5, pk, &k, &i); //bell
	
	binary_tag[0]=3; //ISP: att.com US
	binary_tag[1]='a'; binary_tag[2]='t'; binary_tag[3]='t';
	binary_tag[4]=3;
	binary_tag[5]='c'; binary_tag[6]='o'; binary_tag[7]='m';
	binary_tag[8]=0x00; //ends with 0x00
	binary_tag[9]=0x00; binary_tag[10]=0x01; binary_tag[11]=0x00; binary_tag[12]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 13, pk, &k, &i); //att.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 9, pk, &k, &i); //att.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i); //att
	
	binary_tag[0]=7; //ISP: verizon.com US
	binary_tag[1]='v'; binary_tag[2]='e'; binary_tag[3]='r'; binary_tag[4]='i'; binary_tag[5]='z'; binary_tag[6]='o'; binary_tag[7]='n';
	binary_tag[8]=3;
	binary_tag[9]='c'; binary_tag[10]='o'; binary_tag[11]='m';
	binary_tag[12]=0x00; //ends with 0x00
	binary_tag[13]=0x00; binary_tag[14]=0x01; binary_tag[15]=0x00; binary_tag[16]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 17, pk, &k, &i); //verizon.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 13, pk, &k, &i); //verizon.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i); //verizon
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 7, pk, &k, &i); //verizon (word anywhere)
	
	binary_tag[0]=6; //ISP: virgin.com US
	binary_tag[1]='v'; binary_tag[2]='i'; binary_tag[3]='r'; binary_tag[4]='g'; binary_tag[5]='i'; binary_tag[6]='n';
	binary_tag[7]=3;
	binary_tag[8]='c'; binary_tag[9]='o'; binary_tag[10]='m';
	binary_tag[11]=0x00; //ends with 0x00
	binary_tag[12]=0x00; binary_tag[13]=0x01; binary_tag[14]=0x00; binary_tag[15]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 16, pk, &k, &i); //virgin.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 12, pk, &k, &i); //virgin.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 7, pk, &k, &i); //virgin
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 6, pk, &k, &i); //virgin (word anywhere)
	
//Airlines
	binary_tag[0]=6; //Airlines: etihad.com
	binary_tag[1]='e'; binary_tag[2]='t'; binary_tag[3]='i'; binary_tag[4]='h'; binary_tag[5]='a'; binary_tag[6]='d';
	binary_tag[7]=3;
	binary_tag[8]='c'; binary_tag[9]='o'; binary_tag[10]='m';
	binary_tag[11]=0x00; //ends with 0x00
	binary_tag[12]=0x00; binary_tag[13]=0x01; binary_tag[14]=0x00; binary_tag[15]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 16, pk, &k, &i); //etihad.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 12, pk, &k, &i); //etihad.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 7, pk, &k, &i); //etihad
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 6, pk, &k, &i); //etihad (word anywhere)
	
	binary_tag[0]=6; //Airlines: united.com
	binary_tag[1]='u'; binary_tag[2]='n'; binary_tag[3]='i'; binary_tag[4]='t'; binary_tag[5]='e'; binary_tag[6]='d';
	binary_tag[7]=3;
	binary_tag[8]='c'; binary_tag[9]='o'; binary_tag[10]='m';
	binary_tag[11]=0x00; //ends with 0x00
	binary_tag[12]=0x00; binary_tag[13]=0x01; binary_tag[14]=0x00; binary_tag[15]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 16, pk, &k, &i); //united.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 12, pk, &k, &i); //united.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 7, pk, &k, &i); //united
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 6, pk, &k, &i); //united (word anywhere)

	binary_tag[0]=6; //Airlines: qantas.com
	binary_tag[1]='q'; binary_tag[2]='a'; binary_tag[3]='n'; binary_tag[4]='t'; binary_tag[5]='a'; binary_tag[6]='s';
	binary_tag[7]=3;
	binary_tag[8]='c'; binary_tag[9]='o'; binary_tag[10]='m';
	binary_tag[11]=0x00; //ends with 0x00
	binary_tag[12]=0x00; binary_tag[13]=0x01; binary_tag[14]=0x00; binary_tag[15]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 16, pk, &k, &i); //qantas.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 12, pk, &k, &i); //qantas.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 7, pk, &k, &i); //qantas
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 6, pk, &k, &i); //qantas (word anywhere)
	
	binary_tag[0]=7; //Airlines: airasia.com
	binary_tag[1]='a'; binary_tag[2]='i'; binary_tag[3]='r'; binary_tag[4]='a'; binary_tag[5]='s'; binary_tag[6]='i'; binary_tag[7]='a';
	binary_tag[8]=3;
	binary_tag[9]='c'; binary_tag[10]='o'; binary_tag[11]='m';
	binary_tag[12]=0x00; //ends with 0x00
	binary_tag[13]=0x00; binary_tag[14]=0x01; binary_tag[15]=0x00; binary_tag[16]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 17, pk, &k, &i); //airasia.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 13, pk, &k, &i); //airasia.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i); //airasia
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 7, pk, &k, &i); //airasia (word anywhere)

	binary_tag[0]=5; //Airlines: delta.com
	binary_tag[1]='d'; binary_tag[2]='e'; binary_tag[3]='l'; binary_tag[4]='t'; binary_tag[5]='a';
	binary_tag[6]=3;
	binary_tag[7]='c'; binary_tag[8]='o'; binary_tag[9]='m';
	binary_tag[10]=0x00; //ends with 0x00
	binary_tag[11]=0x00; binary_tag[12]=0x01; binary_tag[13]=0x00; binary_tag[14]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 15, pk, &k, &i); //delta.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 11, pk, &k, &i); //delta.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 6, pk, &k, &i); //delta
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 5, pk, &k, &i); //delta (word anywhere)

	binary_tag[0]=8; //Airlines: emirates.com
	binary_tag[1]='e'; binary_tag[2]='m'; binary_tag[3]='i'; binary_tag[4]='r'; binary_tag[5]='a'; binary_tag[6]='t'; binary_tag[7]='e'; binary_tag[8]='s';
	binary_tag[9]=3;
	binary_tag[10]='c'; binary_tag[11]='o'; binary_tag[12]='m';
	binary_tag[13]=0x00; //ends with 0x00
	binary_tag[14]=0x00; binary_tag[15]=0x01; binary_tag[16]=0x00; binary_tag[17]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 18, pk, &k, &i); //emirates.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 14, pk, &k, &i); //emirates.com
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 9, pk, &k, &i); //emirates

/*
britishairways.com
airfrance.com
malaysiaairlines.com
*/

//Generic
	binary_tag[0]=4; //mail
	binary_tag[1]='m'; binary_tag[2]='a'; binary_tag[3]='i'; binary_tag[4]='l';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 5, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 4, pk, &k, &i); //mail (word anywhere)
	
	binary_tag[0]=3; //ftp
	binary_tag[1]='f'; binary_tag[2]='t'; binary_tag[3]='p';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 3, pk, &k, &i); //ftp (word anywhere)
	
	binary_tag[0]=7; //in-addr
	binary_tag[1]='i'; binary_tag[2]='n'; binary_tag[3]='-';
	binary_tag[4]='a'; binary_tag[5]='d'; binary_tag[6]='d'; binary_tag[7]='r';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 7, pk, &k, &i); //in-addr (word anywhere)
	
	binary_tag[0]=4; //arpa
	binary_tag[1]='a'; binary_tag[2]='r'; binary_tag[3]='p'; binary_tag[4]='a';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 5, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 4, pk, &k, &i);	
	
	binary_tag[0]=4; //news
	binary_tag[1]='n'; binary_tag[2]='e'; binary_tag[3]='w'; binary_tag[4]='s';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 5, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 4, pk, &k, &i);
	
	binary_tag[0]=8; //blogspot
	binary_tag[1]='b'; binary_tag[2]='l'; binary_tag[3]='o'; binary_tag[4]='g';
	binary_tag[5]='s'; binary_tag[6]='p'; binary_tag[7]='o'; binary_tag[8]='t';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 9, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 8, pk, &k, &i); //(anywhere)

	binary_tag[0]=9; //googleads
	binary_tag[1]='g'; binary_tag[2]='o'; binary_tag[3]='o'; binary_tag[4]='g'; binary_tag[5]='l'; binary_tag[6]='e';
	binary_tag[7]='a'; binary_tag[8]='d'; binary_tag[9]='s';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 10, pk, &k, &i);
	
	binary_tag[0]=17; //googlesyndication
	binary_tag[1]='g'; binary_tag[2]='o'; binary_tag[3]='o'; binary_tag[4]='g'; binary_tag[5]='l'; binary_tag[6]='e'; 
	binary_tag[7]='s'; binary_tag[8]='y'; binary_tag[9]='n'; 
	binary_tag[10]='d'; binary_tag[11]='i'; binary_tag[12]='c';
	binary_tag[13]='a'; binary_tag[14]='t'; binary_tag[15]='i';
	binary_tag[16]='o'; binary_tag[17]='n';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 18, pk, &k, &i);
	
	binary_tag[0]=10; //googleapis
	binary_tag[1]='g'; binary_tag[2]='o'; binary_tag[3]='o'; binary_tag[4]='g'; binary_tag[5]='l'; binary_tag[6]='e';
	binary_tag[7]='a'; binary_tag[8]='p'; binary_tag[9]='i'; binary_tag[10]='s';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 11, pk, &k, &i);
	
	binary_tag[0]=6; //akamai
	binary_tag[1]='a'; binary_tag[2]='k'; binary_tag[3]='a'; binary_tag[4]='m'; binary_tag[5]='a'; binary_tag[6]='i';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 7, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i],  (binary_tag+1), 6, pk, &k, &i); //(anywhere)
	
	binary_tag[0]=7; //gizmodo
	binary_tag[1]='g'; binary_tag[2]='i'; binary_tag[3]='z'; binary_tag[4]='m'; binary_tag[5]='o'; binary_tag[6]='d'; binary_tag[7]='o';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i],  (binary_tag+1), 7, pk, &k, &i); //(anywhere)
	
	binary_tag[0]=8; //engadget
	binary_tag[1]='e'; binary_tag[2]='n'; binary_tag[3]='g'; binary_tag[4]='a';
	binary_tag[5]='d'; binary_tag[6]='g'; binary_tag[7]='e'; binary_tag[8]='t';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 9, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 8, pk, &k, &i); //(anywhere)
	
	binary_tag[0]=6; //akadns
	binary_tag[1]='a'; binary_tag[2]='k'; binary_tag[3]='a'; binary_tag[4]='d'; binary_tag[5]='n'; binary_tag[6]='s';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 7, pk, &k, &i);
	
	binary_tag[0]=6; //static
	binary_tag[1]='s'; binary_tag[2]='t'; binary_tag[3]='a'; binary_tag[4]='t'; binary_tag[5]='i'; binary_tag[6]='c';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 7, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 6, pk, &k, &i);
	
	binary_tag[0]=6; //mirror
	binary_tag[1]='m'; binary_tag[2]='i'; binary_tag[3]='r'; binary_tag[4]='r'; binary_tag[5]='o'; binary_tag[6]='r';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 7, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 6, pk, &k, &i);
	
	binary_tag[0]=9; //edgesuite
	binary_tag[1]='e'; binary_tag[2]='d'; binary_tag[3]='g'; binary_tag[4]='e'; binary_tag[5]='s'; binary_tag[6]='u';
	binary_tag[7]='i'; binary_tag[8]='t'; binary_tag[9]='e';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 10, pk, &k, &i);
	
	binary_tag[0]=4; //edge
	binary_tag[1]='e'; binary_tag[2]='d'; binary_tag[3]='g'; binary_tag[4]='e';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 5, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 4, pk, &k, &i); //edge (word anywhere)

	binary_tag[0]=4; //cdn
	binary_tag[1]='c'; binary_tag[2]='d'; binary_tag[3]='n';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 3, pk, &k, &i); //cdn (word anywhere)
	
//Generic (word anywhere)
	ts_add_str_templ_tag(&ts_templ_dns[i], "ads", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_dns[i], "videos", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_dns[i], "video", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_dns[i], "images", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_dns[i], "image", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_dns[i], "movies", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_dns[i], "movie", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_dns[i], "photos", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_dns[i], "photo", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_dns[i], "porn", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_dns[i], "adult", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_dns[i], "online", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_dns[i], "seo", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_dns[i], "cart", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_dns[i], "google", pk, &k, &i);


//Start and end domain
	binary_tag[0]=3; //.com
	binary_tag[1]='c'; binary_tag[2]='o'; binary_tag[3]='m';
	binary_tag[4]=0x00; //ends with 0x00
	binary_tag[5]=0x00; binary_tag[6]=0x01; binary_tag[7]=0x00; binary_tag[8]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 9, pk, &k, &i);	
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 5, pk, &k, &i);
	
	binary_tag[0]=3; //.com - for CDNs
	binary_tag[1]='c'; binary_tag[2]='o'; binary_tag[3]='m';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);
	
	binary_tag[0]=3; //.org
	binary_tag[1]='o'; binary_tag[2]='r'; binary_tag[3]='g';
	binary_tag[4]=0x00; //ends with 0x00
	binary_tag[5]=0x00; binary_tag[6]=0x01; binary_tag[7]=0x00; binary_tag[8]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 9, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 5, pk, &k, &i);
	
	binary_tag[0]=3; //.net
	binary_tag[1]='n'; binary_tag[2]='e'; binary_tag[3]='t';
	binary_tag[4]=0x00; //ends with 0x00
	binary_tag[5]=0x00; binary_tag[6]=0x01; binary_tag[7]=0x00; binary_tag[8]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 9, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 5, pk, &k, &i);
	
	binary_tag[0]=3; //.edu
	binary_tag[1]='e'; binary_tag[2]='d'; binary_tag[3]='u';
	binary_tag[4]=0x00; //ends with 0x00
	binary_tag[5]=0x00; binary_tag[6]=0x01; binary_tag[7]=0x00; binary_tag[8]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 9, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 5, pk, &k, &i);
	
	binary_tag[0]=3; //.gov
	binary_tag[1]='g'; binary_tag[2]='o'; binary_tag[3]='v';
	binary_tag[4]=0x00; //ends with 0x00
	binary_tag[5]=0x00; binary_tag[6]=0x01; binary_tag[7]=0x00; binary_tag[8]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 9, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 5, pk, &k, &i);
	
	binary_tag[0]=3; //www
	binary_tag[1]='w'; binary_tag[2]='w'; binary_tag[3]='w';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);

	binary_tag[0]=2; //co.in
	binary_tag[1]='c'; binary_tag[2]='o';
	binary_tag[3]=2;
	binary_tag[4]='i'; binary_tag[5]='n';
	binary_tag[6]=0x00; //ends with 0x00
	binary_tag[7]=0x00; binary_tag[8]=0x01; binary_tag[9]=0x00; binary_tag[10]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 11, pk, &k, &i);	
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 7, pk, &k, &i);
	
	
	binary_tag[0]=2; //co.fr
	binary_tag[1]='c'; binary_tag[2]='o';
	binary_tag[3]=2;
	binary_tag[4]='f'; binary_tag[5]='r';
	binary_tag[6]=0x00; //ends with 0x00
	binary_tag[7]=0x00; binary_tag[8]=0x01; binary_tag[9]=0x00; binary_tag[10]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 11, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 7, pk, &k, &i);

	binary_tag[0]=2; //co.uk
	binary_tag[1]='c'; binary_tag[2]='o';
	binary_tag[3]=2;
	binary_tag[4]='u'; binary_tag[5]='k';
	binary_tag[6]=0x00; //ends with 0x00
	binary_tag[7]=0x00; binary_tag[8]=0x01; binary_tag[9]=0x00; binary_tag[10]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 11, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 7, pk, &k, &i);
	
	
	binary_tag[0]=2; //.us
	binary_tag[1]='u'; binary_tag[2]='s';
	binary_tag[3]=0x00; //ends with 0x00
	binary_tag[4]=0x00; binary_tag[5]=0x01; binary_tag[6]=0x00; binary_tag[7]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);
	
	binary_tag[0]=2; //.ca
	binary_tag[1]='c'; binary_tag[2]='a';
	binary_tag[3]=0x00; //ends with 0x00
	binary_tag[4]=0x00; binary_tag[5]=0x01; binary_tag[6]=0x00; binary_tag[7]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);
	
	binary_tag[0]=2; //.fr
	binary_tag[1]='f'; binary_tag[2]='r';
	binary_tag[3]=0x00; //ends with 0x00
	binary_tag[4]=0x00; binary_tag[5]=0x01; binary_tag[6]=0x00; binary_tag[7]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);
	
	binary_tag[0]=2; //.it
	binary_tag[1]='i'; binary_tag[2]='t';
	binary_tag[3]=0x00; //ends with 0x00
	binary_tag[4]=0x00; binary_tag[5]=0x01; binary_tag[6]=0x00; binary_tag[7]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);
	
	binary_tag[0]=2; //.de - Germany
	binary_tag[1]='d'; binary_tag[2]='e';
	binary_tag[3]=0x00; //ends with 0x00
	binary_tag[4]=0x00; binary_tag[5]=0x01; binary_tag[6]=0x00; binary_tag[7]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);
	
	binary_tag[0]=2; //.in
	binary_tag[1]='i'; binary_tag[2]='n';
	binary_tag[3]=0x00; //ends with 0x00
	binary_tag[4]=0x00; binary_tag[5]=0x01; binary_tag[6]=0x00; binary_tag[7]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);

	binary_tag[0]=2; //.ae
	binary_tag[1]='a'; binary_tag[2]='e';
	binary_tag[3]=0x00; //ends with 0x00
	binary_tag[4]=0x00; binary_tag[5]=0x01; binary_tag[6]=0x00; binary_tag[7]=0x01; //ends with 0x00 0x01 0x00 0x01
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);

//Nameserver series	
	binary_tag[0]=3; //ns1
	binary_tag[1]='n'; binary_tag[2]='s'; binary_tag[3]='1';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);
	
	binary_tag[0]=3; //ns2
	binary_tag[1]='n'; binary_tag[2]='s'; binary_tag[3]='2';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);
	
	binary_tag[0]=3; //ns3
	binary_tag[1]='n'; binary_tag[2]='s'; binary_tag[3]='3';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);

	binary_tag[0]=3; //ns4
	binary_tag[1]='n'; binary_tag[2]='s'; binary_tag[3]='4';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);
	
	binary_tag[0]=3; //ns5
	binary_tag[1]='n'; binary_tag[2]='s'; binary_tag[3]='5';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);
	
	binary_tag[0]=3; //ns6
	binary_tag[1]='n'; binary_tag[2]='s'; binary_tag[3]='6';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);

	//Questions 00 01, Answer 00 01, Authority 00 00, Additional PRs 00 00
	binary_tag[0]=0x00; binary_tag[1]=0x01; binary_tag[2]=0x00; binary_tag[3]=0x01;
	binary_tag[4]=0x00; binary_tag[5]=0x00; binary_tag[6]=0x00; binary_tag[7]=0x00;
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i);
	binary_tag[2]=0x00; binary_tag[3]=0x00; //Answer 00 00
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 8, pk, &k, &i);

//Type Class TTL, etc
	//Host Address
	binary_tag[0]=0x00; binary_tag[1]=0x01; binary_tag[2]=0x00; binary_tag[3]=0x01;
	binary_tag[4]=0x00; binary_tag[5]=0x00; binary_tag[6]=0x00; //TTL
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 7, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);

	//IPV6 Addr
	binary_tag[0]=0x00; binary_tag[1]=0x1c; binary_tag[2]=0x00; binary_tag[3]=0x01;
	binary_tag[4]=0x00; binary_tag[5]=0x00; binary_tag[6]=0x00; //TTL
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 7, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);

	//PTR
	binary_tag[0]=0x00; binary_tag[1]=0x0c; binary_tag[2]=0x00; binary_tag[3]=0x01;
	binary_tag[4]=0x00; binary_tag[5]=0x00; binary_tag[6]=0x00; //TTL
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 7, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);
	
	//SOA
	binary_tag[0]=0x00; binary_tag[1]=0x06; binary_tag[2]=0x00; binary_tag[3]=0x01;
	binary_tag[4]=0x00; binary_tag[5]=0x00; binary_tag[6]=0x00; //TTL
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 7, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);

	//0x01 0 0x01 0
	binary_tag[0]=0x01; binary_tag[1]='0'; binary_tag[2]=0x01; binary_tag[3]='0';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);
	
	//0x03 224 (multicasts)
	binary_tag[0]=0x03; binary_tag[1]='2'; binary_tag[2]='2'; binary_tag[3]='4';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);
	
	//0x03 192 (private ips)
	binary_tag[0]=0x03; binary_tag[1]='1'; binary_tag[2]='9'; binary_tag[3]='2';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);
	
	//0x03 168 (private ips)
	binary_tag[0]=0x03; binary_tag[1]='1'; binary_tag[2]='6'; binary_tag[3]='8';
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 4, pk, &k, &i);

//All unmatched domains with ending patterns alone. i.e xyz.com 0x00 0x00 0x01 0x00 0x01 & anywhere 0x00 0x01 0x00 0x01 
	binary_tag[0]=0x00; //ends with 0x00
	binary_tag[1]=0x00; binary_tag[2]=0x01; binary_tag[3]=0x00; binary_tag[4]=0x01;
	ts_add_bnry_templ_tag(&ts_templ_dns[i], binary_tag, 5, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_dns[i], (binary_tag+1), 4, pk, &k, &i); //0x00 0x01 0x00 0x01 (anywhere)

	ts_templ_dns_count = i;
} /* init_ts_templ_dns */

void init_ts_templ_telnet()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk='~';
	int i=0; 

	ts_add_str_templ_tag(&ts_templ_telnet[i], "password", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "Password", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "configure", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "Configure", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "command", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "Command", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "configuration", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "information", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "interface", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "hostname", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "--More--", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "history", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "running", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "default", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "passwd", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "enable", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "reload", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "system", pk, &k, &i);	
	ts_add_str_templ_tag(&ts_templ_telnet[i], "change", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "Change", pk, &k, &i);	
	ts_add_str_templ_tag(&ts_templ_telnet[i], "reset", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "login", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "value", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "clear", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "write", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "Write", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "erase", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "exit", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "quit", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "help", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "show", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "Show", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "save", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "name", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "user", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "mode", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "snmp", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "sntp", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "ftp", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_telnet[i], "ssh", pk, &k, &i);

	ts_templ_telnet_count = i;
} /* init_ts_templ_telnet */

void init_ts_templ_imap()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk='~';
	int i=0, j=0; 

	for(j=20;j>=3;j--)
	{	ts_add_str_templ_common_tag(&ts_templ_imap[i], ' ', j, pk, &k, &i); }
	
	ts_add_str_templ_tag(&ts_templ_imap[i], "UID", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "FETCH", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "HEADER", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "BODY", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "SIZE", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "FLAGS", pk, &k, &i);
	
	ts_add_str_templ_tag(&ts_templ_imap[i], "To: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "From: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "Date: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "Subject: ", pk, &k, &i);	
	ts_add_str_templ_tag(&ts_templ_imap[i], "Received: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "X-Mailer: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "Message-ID: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "Envelope-to: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "Return-path: ", pk, &k, &i);	
	ts_add_str_templ_tag(&ts_templ_imap[i], "MIME-Version: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "Content-Type: ", pk, &k, &i);	
	ts_add_str_templ_tag(&ts_templ_imap[i], "Thread-Index: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "Delivery-date: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "Content-Language: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "X-Identified-User: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "Content-Disposition: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "Content-Transfer-Encoding: ", pk, &k, &i);
		
	ts_add_str_templ_tag(&ts_templ_imap[i], "filename=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "boundary=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "vlink=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "class=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "name=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "ppda=", pk, &k, &i);
	
	ts_add_str_templ_tag(&ts_templ_imap[i], "envelope-from", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "multipart/mixed", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "from", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "completed", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_imap[i], "base64", pk, &k, &i);
	
	ts_add_str_templ_tag(&ts_templ_imap[i], "xmlns:", pk, &k, &i);
	
	ts_templ_imap_count = i;
} /* init_ts_templ_imap */

void init_ts_templ_mapi()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk='~';
	int i=0; 

	ts_add_str_templ_tag(&ts_templ_mapi[i], " ", pk, &k, &i);
	
	ts_templ_mapi_count = i;
} /* init_ts_templ_mapi */

void init_ts_templ_ftp()
{	BYTE k = 0x00; //Key series start pos !
	BYTE pk = '~';
	int i=0; 

	ts_add_str_templ_tag(&ts_templ_ftp[i], "421 Timeout.\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "421 Home directory not available - aborting\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "227 Entering Passive Mode ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "226 Logout.\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "226 Directory send OK.\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "150 Here comes the directory listing.\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "550 Failed to open file.\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "550 Could not get file modification time.\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "550 ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "530 Logout.\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "530 Login authentication failed\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "331 User anonymous OK. Password required\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "200 Switching to Binary mode.\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "250 Directory successfully changed.\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "250 CWD command successful\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], " Opening ASCII mode data connection for file list\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], " is the current directory\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "Transfer complete\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "Quotas off\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "RMD command successful\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "CWD command successful\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "DELE command successful\r\n", pk, &k, &i);
	
	ts_add_str_templ_tag(&ts_templ_ftp[i], "Directory", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "directory", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "current", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "Files", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "File", pk, &k, &i); //file added in generic templating
	ts_add_str_templ_tag(&ts_templ_ftp[i], "list", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "binary", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "the", pk, &k, &i);
	
  	ts_add_str_templ_tag(&ts_templ_ftp[i], "PASS ", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_ftp[i], "USER anonymous\r\n", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_ftp[i], "USER ", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_ftp[i], "anonymous\r\n", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_ftp[i], "anonymous", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_ftp[i], "230-\t\t\t", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_ftp[i], "230-\t\t", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_ftp[i], "230-\r\n", pk, &k, &i);
  	ts_add_str_templ_tag(&ts_templ_ftp[i], "230-", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "SYST\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "PWD\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "SIZE ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "RETR ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "CWD ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "MDTM ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "DELE ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "LIST\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "PASV\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "FEAT\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "TYPE I\r\n", pk, &k, &i);

//Website generic
   ts_add_str_templ_tag(&ts_templ_ftp[i], "http://www.", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], "http://", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], "https://www.", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], "https://", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], "ftp://www.", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], "ftp://", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], "ftp", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], "rsync://www.", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], "rsync://", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], "pub/", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], "pub", pk, &k, &i);
   
   ts_add_str_templ_tag(&ts_templ_ftp[i], "www.", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], "www", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], ".com/", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], ".com\r\n", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], ".com", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], ".net", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], ".org", pk, &k, &i);
   
//common filename suffix
   ts_add_str_templ_tag(&ts_templ_ftp[i], ".txt", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], ".tgz", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], ".docx", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], ".doc", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], ".ppt", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".pps", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".xlsx", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".xls", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".xml", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], ".odt", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], ".sql", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], ".exe", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], ".asc", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], ".pdf", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".png", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".jpg", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".mp3", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".mpg", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".log", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".iso", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".pkg", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".dll", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".html", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".htm", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".php", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".zip", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".rar", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".rpm", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".spec", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".diff", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".tar.gz", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".tar.xz", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".tar.bz2", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".tar.sign", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".tar", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".pcapng", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".pcap", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], ".patch", pk, &k, &i);
	
//common filenames
   ts_add_str_templ_tag(&ts_templ_ftp[i], "readme", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], "README", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], "patch", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], "release", pk, &k, &i);
   
//Tabs - '\t' is covered in common templating.

//File permissions
	ts_add_str_templ_tag(&ts_templ_ftp[i], "dr--", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "-r--r--r--", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "r--r--r--", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "-r--", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], "r--", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ftp[i], "drwx", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "rwx", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "rws", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "r-x", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "rw-", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ftp[i], "       ", pk, &k, &i); //sometimes to prevent common templating
	ts_add_str_templ_tag(&ts_templ_ftp[i], "      ", pk, &k, &i); //sometimes to prevent common templating
	ts_add_str_templ_tag(&ts_templ_ftp[i], "     ", pk, &k, &i); //sometimes to prevent common templating
	ts_add_str_templ_tag(&ts_templ_ftp[i], "    ", pk, &k, &i); //sometimes to prevent common templating
	ts_add_str_templ_tag(&ts_templ_ftp[i], "\r\n-", pk, &k, &i);
        
//Dates
  ts_add_str_templ_tag(&ts_templ_ftp[i], " Jan ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ftp[i], " Feb ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ftp[i], " Mar ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ftp[i], " Apr ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ftp[i], " May ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ftp[i], " Jun ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ftp[i], " Jul ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ftp[i], " Aug ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ftp[i], " Sep ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ftp[i], " Oct ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ftp[i], " Nov ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ftp[i], " Dec ", pk, &k, &i);
     
//Pure-FTPd
  ts_add_str_templ_tag(&ts_templ_ftp[i], "----------", pk, &k, &i);
	
	ts_templ_ftp_count = i;
} /* init_ts_templ_ftp */

void init_ts_templ_nfs()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk='~';
	int i=0; 

   ts_add_str_templ_tag(&ts_templ_nfs[i], "", pk, &k, &i);
   
	ts_templ_nfs_count = i;
} /* init_ts_templ_nfs */

void init_ts_templ_mysql()
{	BYTE key=0x00; //Key series start pos !
	BYTE pk='~';
	int i=0; 

	ts_templ_mysql_count = i;
} /* init_ts_templ_mysql */

void init_ts_templ_pgsql()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk='~';
	int i=0; 

//PostgreSQL Control
	ts_add_str_templ_tag(&ts_templ_pgsql[i], "user", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pgsql[i], "database", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pgsql[i], "client_encoding", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pgsql[i], "DateStyle", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pgsql[i], "is_superuser", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pgsql[i], "server_version", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pgsql[i], "session_authorization", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pgsql[i], "begin", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pgsql[i], "BEGIN", pk, &k, &i);

	ts_templ_pgsql_count = i;
   printk("TAGS: ts_templ_pgsql_count:%d - total:%d - free:%d\n", i, MAX_TS_TEMPL_PGSQL, MAX_TS_TEMPL_PGSQL-i);
} /* init_ts_templ_pgsql */


void init_ts_templ_sql()
{	BYTE k=(0x00+50); //Key series start pos !
	BYTE pk='~';
	int i=0; 

//SQL Queries
	ts_add_str_templ_tag(&ts_templ_sql[i], "SHOW VARIABLES", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "show variables", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "SHOW DATABASES", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "DATABASES", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "show databases", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "databases", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "SHOW TABLES", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "TABLES", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "show tables", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "tables", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "SHOW ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "show ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "INSERT INTO ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "insert into ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "INSERT ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "insert ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "SELECT * FROM ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "select * from ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "SELECT ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "select ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "CREATE DATABASE ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "create database ", pk, &k, &i);

   ts_add_str_templ_tag(&ts_templ_sql[i], "ALTER ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "alter ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "JOIN", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "join", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "LEFT JOIN", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "left join", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "LEFT", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "left", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "BETWEEN", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "between", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "AND", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "and", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "FROM", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "from", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "WHERE", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "where", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "USE ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "use ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "COMMIT", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "commit", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "DISTINCT", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "distinct", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "UNIQUE", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "unique", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "CONSTRAINT", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "constraint", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "DATABASE", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "database", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "TABLE", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "table", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "INDEX", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "index", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "DROP", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "drop", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "UNION", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "union", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "DESC", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "desc", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "ORDER BY", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "order by", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "order", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "LIMIT", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "limit", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "ALL", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "all", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "SQL", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "sql", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "TRIGGERS", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "triggers", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "PROCEDURE", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "procedure", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "FUNCTION", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "function", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "STATUS", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "status", pk, &k, &i);

//SQL Functions
   ts_add_str_templ_tag(&ts_templ_sql[i], "NOW()", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "now()", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "COUNT(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "count(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "ROUND(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "round(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "AVG(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "avg(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "FIRST(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "first(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "LAST(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "last(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "MAX(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "max(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "MIN(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "min(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "SUM(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "sum(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "GROUP BY", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "group by", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "GROUP", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "group", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "HAVING", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "having", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "UCASE(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "ucase(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "LCASE(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "lcase(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "MID(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "mid(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "LEN(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "len(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "FORMAT(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "format(", pk, &k, &i);

//SQL Datatypes
   ts_add_str_templ_tag(&ts_templ_sql[i], "UNSIGNED", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "unsigned", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "VARCHAR(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "varchar(", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "VARCHAR", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "varchar", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_sql[i], "INT", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "int", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "PRIMARY KEY", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "primary key", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "PRIMARY", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "primary", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "AUTO_INCREMENT", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "auto_increment", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "DEFAULT", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "default", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "NULL", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "null", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "COLLATE", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "collate", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "ENGINE", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "engine", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "VARIABLES", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_sql[i], "variables", pk, &k, &i);
	
	ts_templ_sql_count = i;
} /* init_ts_templ_sql */

void init_ts_templ_mssql()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk='~';
	int i=0; 

	ts_add_str_templ_tag(&ts_templ_mssql[i], "", pk, &k, &i);

	ts_templ_mssql_count = i;
} /* init_ts_templ_mssql */

void init_ts_templ_ssh()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk='~';
	int i=0; 
	char binary_tag[60]; memset(binary_tag, 0x00, 60);

  ts_add_str_templ_tag(&ts_templ_ssh[i], "SSH-", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "OpenSSH", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "diffie-hellman-group-exchange-sha256,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "diffie-hellman-group-exchange-sha256", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "diffie-hellman-group-exchange-sha1,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "diffie-hellman-group-exchange-sha1", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "ssh-rsa-cert-v00@openssh.com,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "ssh-rsa-cert-v00@openssh.com", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "ssh-dss-cert-v00@openssh.com,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "ssh-dss-cert-v00@openssh.com", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "diffie-hellman-group14-sha1,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "diffie-hellman-group14-sha1", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "rijndael-cbc@lysator.liu.se,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "rijndael-cbc@lysator.liu.se", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "hmac-ripemd160@openssh.com,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "hmac-ripemd160@openssh.com", pk, &k, &i);
  
  //00 00 00 1a(26) diffie-hellman-group1-sha1
  binary_tag[0]=0x00; binary_tag[1]=0x00; binary_tag[2]=0x00; binary_tag[3]=0x1a;
  strcpy((binary_tag+4), "diffie-hellman-group1-sha1");
  ts_add_bnry_templ_tag(&ts_templ_ssh[i], binary_tag, 30, pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "diffie-hellman-group1-sha1,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "diffie-hellman-group1-sha1", pk, &k, &i);
  
  ts_add_str_templ_tag(&ts_templ_ssh[i], "umac-64@openssh.com,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "umac-64@openssh.com", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "zlib@openssh.com,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "zlib@openssh.com", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "hmac-ripemd160,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "hmac-ripemd160", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "hmac-sha1-96,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "hmac-sha1-96", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "blowfish-cbc,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "blowfish-cbc", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "hmac-md5-96,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "hmac-md5-96", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "cast128-cbc,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "cast128-cbc", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "arcfour256,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "arcfour256", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "arcfour128,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "arcfour128", pk, &k, &i);
  
  
  //00 00 00 0a(10) aes128-cbc
  binary_tag[0]=0x00; binary_tag[1]=0x00; binary_tag[2]=0x00; binary_tag[3]=0x0a;
  strcpy((binary_tag+4), "aes128-cbc");
  ts_add_bnry_templ_tag(&ts_templ_ssh[i], binary_tag, 14, pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "aes128-cbc,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "aes128-cbc", pk, &k, &i);

  ts_add_str_templ_tag(&ts_templ_ssh[i], "aes128-ctr,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "aes128-ctr", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "aes192-ctr,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "aes192-ctr", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "aes256-ctr,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "aes256-ctr", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "aes192-cbc,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "aes192-cbc", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "aes256-cbc,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "aes256-cbc", pk, &k, &i);
  
  //00 00 00 09 hmac-sha1
  binary_tag[0]=0x00; binary_tag[1]=0x00; binary_tag[2]=0x00; binary_tag[3]=0x09;
  strcpy((binary_tag+4), "hmac-sha1");
  ts_add_bnry_templ_tag(&ts_templ_ssh[i], binary_tag, 13, pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "hmac-sha1,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "hmac-sha1", pk, &k, &i);
  
  ts_add_str_templ_tag(&ts_templ_ssh[i], "hmac-md5,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "hmac-md5", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "3des-cbc,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "3des-cbc", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "arcfour,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "arcfour", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "zlibnone,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "zlibnone", pk, &k, &i);
  
  //00 00 00 07 ssh-rsa
  binary_tag[0]=0x00; binary_tag[1]=0x00; binary_tag[2]=0x00; binary_tag[3]=0x07;
  strcpy((binary_tag+4), "ssh-rsa");
  ts_add_bnry_templ_tag(&ts_templ_ssh[i], binary_tag, 11, pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "ssh-rsa,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "ssh-rsa", pk, &k, &i);
  
  ts_add_str_templ_tag(&ts_templ_ssh[i], "ssh-dss,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "ssh-dss", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "zlib,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "zlib", pk, &k, &i);
  
  //00 00 00 04 none
  binary_tag[0]=0x00; binary_tag[1]=0x00; binary_tag[2]=0x00; binary_tag[3]=0x04;
  strcpy((binary_tag+4), "none");
  ts_add_bnry_templ_tag(&ts_templ_ssh[i], binary_tag, 8, pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "none,", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssh[i], "none", pk, &k, &i);
  
  binary_tag[0]=0x00; binary_tag[1]=0x00; binary_tag[2]=0x00; binary_tag[3]=0x00;
  binary_tag[4]=0x00; binary_tag[5]=0x00; binary_tag[6]=0x00;
  ts_add_bnry_templ_tag(&ts_templ_ssh[i], binary_tag, 7, pk, &k, &i);
  ts_add_bnry_templ_tag(&ts_templ_ssh[i], binary_tag, 6, pk, &k, &i);
  ts_add_bnry_templ_tag(&ts_templ_ssh[i], binary_tag, 5, pk, &k, &i);
  ts_add_bnry_templ_tag(&ts_templ_ssh[i], binary_tag, 4, pk, &k, &i);

	ts_templ_ssh_count = i;
} /* init_ts_templ_ssh */

void init_ts_templ_ssl()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk='~';
	int i=0;
	char binary_tag[60]; memset(binary_tag, 0x00, 60);
	
  ts_add_str_templ_tag(&ts_templ_ssl[i], "http://www.", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "https://www.", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "http://", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "https://", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "ftp://www.", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "ftp://", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "www.", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "www.verisign.com", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "VeriSign", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "Network", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "Internet", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "International", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "Server", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "Secure", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "Digital", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "Public", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "Primary", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "Trust", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "Global", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "Inc", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "Authority", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "Google", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "apis.google.com", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "mail.google.com", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "accounts.google.com", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "akamai", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "*.google.com", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], ".google.com", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "google.com", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "*.google.co.", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], ".google.co.", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "*.google.", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], ".google.", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "google", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "Certification", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "Certificate", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "image/gif", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], ".com/", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], ".com", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], ".org/", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], ".org", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], ".net", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "ssl", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "cdn", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "bank", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "static", pk, &k, &i);
  
//protocol
  ts_add_str_templ_tag(&ts_templ_ssl[i], "spdy/4a4", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "spdy/3.1", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "spdy/3", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "spdy", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_ssl[i], "http/1.1", pk, &k, &i);

//Binary replacements
	binary_tag[0]=0x17; //Application Data
	binary_tag[1]=0x03; binary_tag[2]=0x01; //Version TLS 1.0
	binary_tag[3]=0x00; //first byte of len (if it is 0x00 still for values <0x00ff)
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
	binary_tag[3]=0x01; //first byte of len (if it is 0x01 still for values <0x01ff)
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
	binary_tag[3]=0x02; //first byte of len (if it is 0x02 still for values <0x02ff)
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
	binary_tag[3]=0x05; //first byte of len (if it is 0x05 still for values <0x05ff) --> Mostly MTU sized packet
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 3, pk, &k, &i);
	
	binary_tag[0]=0x17; //Application Data
	binary_tag[1]=0x03; binary_tag[2]=0x03; //Version TLS 1.2
	binary_tag[3]=0x00; //first byte of len (if it is 0x00 still for values <0x00**)
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
	binary_tag[3]=0x01; //first byte of len (if it is 0x01 still for values <0x01**)
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
	binary_tag[3]=0x02; //first byte of len (if it is 0x02 still for values <0x02**)
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 3, pk, &k, &i);
	
	binary_tag[0]=0x15; //Alert
	binary_tag[1]=0x03; binary_tag[2]=0x01; //Version TLS 1.0
	binary_tag[3]=0x00; //first byte of len (if it is 0x00 still for values <0x00ff)
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
	binary_tag[3]=0x01; //first byte of len (if it is 0x01 still for values <0x01ff)
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 3, pk, &k, &i);
	
		
	binary_tag[0]=0x14; //Change Cipher Spec
	binary_tag[1]=0x03; binary_tag[2]=0x01; //Version TLS 1.0
	binary_tag[3]=0x00; //first byte of len (if it is 0x00 still for values <0x00ff)
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 3, pk, &k, &i);
	
	binary_tag[0]=0x14; //Change Cipher Spec
	binary_tag[1]=0x03; binary_tag[2]=0x03; //Version TLS 1.2
	binary_tag[3]=0x00; //first byte of len (if it is 0x00 still for values <0x00ff)
	binary_tag[4]=0x01; binary_tag[5]=0x01;
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 6, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 3, pk, &k, &i);
	
	binary_tag[0]=0x10; //Client Key Exchange
	binary_tag[1]=0x00; binary_tag[2]=0x00; //Length 0xXX 0xXX 0xXX
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 3, pk, &k, &i);
	
	binary_tag[0]=0x16; //Handshake
	binary_tag[1]=0x03; binary_tag[2]=0x01; //Version TLS 1.0
	binary_tag[3]=0x00; //first byte of len (if it is 0x00 still for values <0x00ff)
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 3, pk, &k, &i);
	
	binary_tag[0]=0x16; //Handshake
	binary_tag[1]=0x03; binary_tag[2]=0x03; //Version TLS 1.2
	binary_tag[3]=0x00; //first byte of len (if it is 0x00 still for values <0x00ff)
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 3, pk, &k, &i);
	
	binary_tag[0]=0x00; binary_tag[1]=0x23; //SessionTicket TLS
	binary_tag[2]=0x00; binary_tag[3]=0x00;
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
	
	binary_tag[0]=0x00; binary_tag[1]=0x12; //Unknown
	binary_tag[2]=0x00; binary_tag[3]=0x00;
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
	
	binary_tag[0]=0x75; binary_tag[1]=0x50; //Unknown
	binary_tag[2]=0x00; binary_tag[3]=0x00;
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
	
	binary_tag[0]=0xff; binary_tag[1]=0x01; //renegotiation info
	binary_tag[2]=0x00; binary_tag[3]=0x01; binary_tag[4]=0x00;
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 5, pk, &k, &i);
	
	binary_tag[0]=0x00; binary_tag[1]=0x0b; //ec_point_formats
	binary_tag[2]=0x00;
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 3, pk, &k, &i);
	
	binary_tag[0]=0x33; binary_tag[1]=0x74; //next_protocol_negotiation
	binary_tag[2]=0x00; binary_tag[3]=0x00;
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 3, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);
		
	binary_tag[0]=0x00; binary_tag[1]=0x00; binary_tag[2]=0x00; binary_tag[3]=0x00;
	binary_tag[4]=0x00; binary_tag[5]=0x00; binary_tag[6]=0x00;
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 7, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 6, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 5, pk, &k, &i);
	ts_add_bnry_templ_tag(&ts_templ_ssl[i], binary_tag, 4, pk, &k, &i);

	ts_templ_ssl_count = i;
} /* init_ts_templ_ssl */

void init_ts_templ_pop()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk='~';
	int i=0; 
   ts_add_str_templ_tag(&ts_templ_pop[i], "Received: ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "unknown ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "HELO ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "(envelope-sender ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "envelope-sender", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "ESMTP", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "SMTP", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "with ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Message-ID: ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Date: ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "User-Agent: Mozilla/", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], " Gecko/", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], " Linux ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], " Lightning/", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], " Thunderbird/", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "User-Agent: ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "MIME-Version: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "Organization: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "To: ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Subject: ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Subject: Re: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "In-Reply-To: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "References: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "for", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "from", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "network", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "qmail", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "by ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "This ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "X-Nonspam: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "Content-Transfer-Encoding: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "Encoding: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "Content-Type: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "format=flowed", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "multipart/alternative", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "This is a multi-part message in MIME format.", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "text/plain;", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "charset=ISO-8859-1;", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "boundary=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "wrote:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "Transitional", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "<!DOCTYPE HTML PUBLIC ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "HTML", pk, &k, &i);
	 
//Generic Engish email keywords			
	ts_add_str_templ_tag(&ts_templ_pop[i], "Hi,", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "Regards", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "Dear", pk, &k, &i);
	
//Tags
   ts_add_str_templ_tag(&ts_templ_pop[i], "<br>", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "<br />", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "<html>", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "</html>", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "<head>", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "</head>", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "<body ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "</body>", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "<title></title>", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "bgcolor=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "<meta ", pk, &k, &i);
     
//Dates
   ts_add_str_templ_tag(&ts_templ_pop[i], " GMT\r\n", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "2010 ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Jan ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Feb ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Mar ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Apr ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "May ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Jun ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Jul ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Aug ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Sep ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Oct ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Nov ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Dec ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Mon, ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Tue, ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Wed, ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Thu, ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Fri, ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Sat, ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "Sun, ", pk, &k, &i);

//Numbers
	ts_add_str_templ_tag(&ts_templ_pop[i], "00:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "01:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "02:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "03:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "04:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "05:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "06:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "07:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "08:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "09:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "10:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "11:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "12:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "13:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "14:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "15:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "16:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "17:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "18:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "19:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "20:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "21:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "22:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "23:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_pop[i], "24:", pk, &k, &i);
	
//domains
   ts_add_str_templ_tag(&ts_templ_pop[i], "pop.", pk, &k, &i);
   
//misc
   ts_add_str_templ_tag(&ts_templ_pop[i], "------------", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_pop[i], "---", pk, &k, &i);
   

	ts_templ_pop_count = i;
} /* init_ts_templ_pop */

void init_ts_templ_smtp()
{	BYTE k = 0x00; //Key series start pos !
	BYTE pk = '~';
	int i=0; 
	
  ts_add_str_templ_tag(&ts_templ_smtp[i], "AUTH LOGIN\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_smtp[i], "Authentication succeeded\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_smtp[i], "Accepted\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_smtp[i], "DATA\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_smtp[i], "EHLO GP\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_smtp[i], "AUTH PLAIN LOGIN\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_smtp[i], "STARTTLS\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_smtp[i], "MAIL FROM:", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_smtp[i], "250 OK\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_smtp[i], "RCPT TO:", pk, &k, &i);
  ts_add_str_templ_tag(&ts_templ_smtp[i], "QUIT\r\n", pk, &k, &i);

	ts_templ_smtp_count = i;
} /* init_ts_templ_smtp */

void init_ts_http_templ_dict()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk='^';
	int i=0; 

//GET or POST
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "GET / HTTP/1.1\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], ".png HTTP/1.1\r\n", pk, &k, &i);  // (.ico is not required since it is added in favicon.ico)
  ts_add_str_templ_tag(&ts_http_templ_dict[i], ".jpg HTTP/1.1\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], ".php HTTP/1.1\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], ".htm HTTP/1.1\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], ".html HTTP/1.1\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], ".js HTTP/1.1\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], " HTTP/1.1\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "GET /", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "GET", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "POST /", pk, &k, &i);

//HTTP
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "HTTP/1.1 200 OK\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "HTTP/1.1 204 No Content\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "HTTP/1.1 302 Found\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "HTTP/1.1 304 Not Modified\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "HTTP/1.1 206 Partial Content\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "HTTP/1.1 400 Bad Request\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "HTTP/1.1 404 Not Found\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "HTTP/1.1 403 Forbidden\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "HTTP/1.1 303 See Other\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "HTTP/1.0 408 Request Time-out\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "HTTP/1.1 101 Switching Protocols\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "HTTP/1.1 ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "HTTP/1.0 ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "HTTP", pk, &k, &i);

//HEAD
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "HEAD / HTTP/1.1\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "HEAD /", pk, &k, &i);

//Full lines
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Connection: keep-alive\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Connection: close\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Accept-Language: en-us,en;q=0.5\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Accept-Language: en-US,en;q=0.8\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Accept-Encoding: gzip,deflate,sdch\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Accept-Encoding: gzip,deflate\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Accept: */*\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Keep-Alive: 115\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Pragma: no-cache\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Cache-Control: no-cache\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Content-Type: text/html; charset=UTF-8\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Content-Type: image/gif\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Content-Type: text/javascript; charset=UTF-8\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Content-Type: image/png\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Content-Type: text/css\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Content-Type: image/x-icon\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Content-Type: text/html; charset=iso-8859-1\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Content-Type: text/html", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Content-Type: application/", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Content-Type: image/jpeg\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Accept-Ranges: bytes\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Access-Control-Allow-Origin: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Access-Control-Allow-Credentials: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Access-Control-Allow-Methods:	", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Cache-Control: private\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Cache-Control: private", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Cache-Control: public", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Content-Encoding: gzip\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Transfer-Encoding: chunked\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Server: Apache\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Server: Apache", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Server: lighttpd", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Server: Microsoft-IIS", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Server: Golfe", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Server: FlashCom", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Connection: Keep-Alive\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "X-Content-Type-Options: nosniff\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Referer: http://", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "X-Powered-By: ASP.NET\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "X-Cache: HIT\r\n", pk, &k, &i);

//header names only
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Connection: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Accept-Language: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Accept: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Host: www.", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "\r\nHost: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Host: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Referer: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Cookie: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Cookie2: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Keep-Alive: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "User-Agent: Mozilla/5.0 ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "User-Agent: AndroidDownloadManager\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "User-Agent: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Pragma: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Cache-Control: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Accept-Charset: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Accept-Encoding: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Content-Length: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Content-Type: application/", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Content-Type: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Age: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Transfer-Encoding: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Accept-Ranges: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Content-Encoding: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Date: Mon, ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Date: Tue, ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Date: Wed, ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Date: Thu, ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Date: Fri, ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Date: Sat, ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Date: Sun, ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Date: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Server: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "X-XSS-Protection: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "X-Content-Type-Options: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], ", 01 Jan 1990 00:00:00 GMT\r\n", pk, &k, &i); //Some default expiry, if not set in server
  
  ///ts_add_str_templ_tag(&ts_http_templ_dict[i], "Expires: Mon, ", pk, &k, &i); no more space for keys
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Expires: ", pk, &k, &i);
  
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Refresh: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "X-Frame-Options: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Set-Cookie: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Location: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "ETag: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Last-Modified: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "If-None-Match: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "If-Modified-Since: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Mime-Version: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Vary: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "TE: ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "X-Powered-By: ", pk, &k, &i);

//Dates
  ts_add_str_templ_tag(&ts_http_templ_dict[i], " GMT\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "2014", pk, &k, &i); //doing here first, if not done via common optimization due to key replacements.
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Jan ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Feb ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Mar ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Apr ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "May ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Jun ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Jul ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Aug ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Sep ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Oct ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Nov ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Dec ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Mon, ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Tue, ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Wed, ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Thu, ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Fri, ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Sat, ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Sun, ", pk, &k, &i);

//Numbers
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "00:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "01:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "02:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "03:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "04:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "05:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "06:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "07:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "08:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "09:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "10:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "11:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "12:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "13:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "14:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "15:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "16:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "17:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "18:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "19:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "20:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "21:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "22:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "23:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "24:", pk, &k, &i);

//Misc
  ts_add_str_templ_tag(&ts_http_templ_dict[i], ".com\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], ".com/", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "cdn.", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "ads", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "blogspot", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "blog", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], " Mozilla/", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], " Gecko/", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], " Fedora/", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], " Firefox/", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], " Chrome/", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], " Opera/", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], " Safari/", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "Version/", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], " Linux ", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "i686", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "\r\n\r\n", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "PHPSESSID=", pk, &k, &i);
  ts_add_str_templ_tag(&ts_http_templ_dict[i], "ID=", pk, &k, &i);

//Partial matches
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "en-us", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "en-US", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "text", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "max-age", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "PREF", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "gzip\r\n", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "deflate, ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "deflate", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "identity, ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "identity", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "entity", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "trailers, ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "trailers", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "chunked, ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "chunked", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "x-gzip, ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "x-gzip", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "x-xbitmap", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "gzip, ", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "gzip", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "mode=block", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "block", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "mode", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "private", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "no-cache", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "no-store", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "proxy-revalidate", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "application/xhtml", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "application/xml", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "application", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "images", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "image", pk, &k, &i);     
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "text/html", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "Keep-Alive", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "html", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "iso-8859-1", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "utf-8", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "xhtml", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "xml", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "keywords", pk, &k, &i);
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "video", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "jquery", pk, &k, &i);


//Cookie
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "__gads=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "__utma=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "__utmz=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "utmcsr=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "utmctr=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "utmccn=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "utmcmd=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "(none)", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "(direct)", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "(referral)", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "referral", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "path=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "expires=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "domain=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], "policyref=", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], " NOI", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], " BUS", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], " OUR", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], " NAV", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], " OTC", pk, &k, &i);
	ts_add_str_templ_tag(&ts_http_templ_dict[i], " UNI", pk, &k, &i);

//HTTP -> HTML redirects (permanently moved into bla bla bla...)      
   ts_add_str_templ_tag(&ts_http_templ_dict[i], "Permanently", pk, &k, &i);
   

	ts_http_templ_dict_count = i;
} /* init_ts_http_templ_dict */

void init_ts_templ_ica()
{	BYTE k = 0x00; //Key series start pos !
	BYTE pk='~';
	int i=0; 

   ts_add_str_templ_tag(&ts_templ_ica[i], "ICA-", pk, &k, &i);
        
	ts_templ_ica_count = i;
} /* init_ts_templ_ica */

void init_ts_templ_rdp()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk='~';
	int i=0; 
   ts_add_str_templ_tag(&ts_templ_rdp[i], "RDP-", pk, &k, &i);
        
	ts_templ_ica_count = i;
} /* init_ts_templ_rdp */

void init_ts_templ_spice()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk='~';
	int i=0; 
	ts_add_str_templ_tag(&ts_templ_spice[i], "SPICE-", pk, &k, &i);
        
	ts_templ_spice_count = i;
} /* init_ts_templ_spice */

void init_ts_templ_voip()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk='~';
	int i=0; 
	ts_add_str_templ_tag(&ts_templ_voip[i], "VOIP-", pk, &k, &i);
        
	ts_templ_voip_count = i;
} /* init_ts_templ_voip */

void init_ts_templ_sip()
{	BYTE k=0x00; //Key series start pos !
	BYTE pk='~';
	int i=0; 

 ts_add_str_templ_tag(&ts_templ_sip[i], "Via: SIP/2.0/UDP ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Via: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "From: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "To: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Call-ID: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Call-id: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "test@", pk, &k, &i); //username - test
 ts_add_str_templ_tag(&ts_templ_sip[i], ":5060\r\n", pk, &k, &i); //sip-port (5060)\r\n
 ts_add_str_templ_tag(&ts_templ_sip[i], ":5060 ", pk, &k, &i); //sip-port (5060)
 ts_add_str_templ_tag(&ts_templ_sip[i], ":5060", pk, &k, &i); //sip-port (5060)
 ts_add_str_templ_tag(&ts_templ_sip[i], ":5090\r\n", pk, &k, &i); //sip-port (5090)\r\n
 ts_add_str_templ_tag(&ts_templ_sip[i], ":5090 ", pk, &k, &i); //sip-port (5090)
 ts_add_str_templ_tag(&ts_templ_sip[i], ":5090", pk, &k, &i); //sip-port (5090)
 ts_add_str_templ_tag(&ts_templ_sip[i], "CSeq: ", pk, &k, &i);
 
 ts_add_str_templ_tag(&ts_templ_sip[i], "Allow: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "User-Agent: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Expires: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Accept: application/sdp", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Accept: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Content-Type: application/sdp\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Content-Type: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Event: keep-alive\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Event: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Route: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Content-Length: 0\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Content-Length: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Contact: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Warning: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Proxy-Authorization: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Max-Forwards: ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "RTSP/1.0 200 OK\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "RTSP/1.0 100 Trying\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "RTSP/1.0 400 Bad Request\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "RTSP/1.0 407 Proxy Authentication Required\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "RTSP/1.0 ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "SIP/2.0 200 OK\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "SIP/2.0 180 Ringing\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "SIP/2.0 100 Trying\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "SIP/2.0", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "P-Associated-URI: ", pk, &k, &i);
 
 ts_add_str_templ_tag(&ts_templ_sip[i], "INVITE", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "application/sdp", pk, &k, &i); 
 ts_add_str_templ_tag(&ts_templ_sip[i], "INVITE, ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "INVITE", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "ACK, ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "ACK", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "CANCEL, ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "CANCEL", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "BYE, ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "BYE", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "SUBSCRIBE", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "REFER, ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "REFER", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "REGISTER\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "REGISTER", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "OPTIONS, ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "OPTIONS", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "NOTIFY, ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "NOTIFY\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "NOTIFY", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "INFO, ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "INFO", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "DIGEST", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "PRACK", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "UPDATE", pk, &k, &i);
 
 ts_add_str_templ_tag(&ts_templ_sip[i], "m=audio ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "RTP/AVP", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "SIPPS", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "o=SIPPS ", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "call", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "Digest", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "pcma", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "mode", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "rport", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "sip:", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "voip", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "response=", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "received=", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "username=", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "expires=", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "branch=", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "realm=", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "cnonce=", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "nonce=", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "line=", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "user=", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "tag=", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "uri=", pk, &k, &i);

//SDP
 ts_add_str_templ_tag(&ts_templ_sip[i], "a=rtpmap:13 CN/8000\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "a=rtpmap:18 G729/8000\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "a=rtpmap:0 PCMU/8000\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "a=rtpmap:96 telephone-event/8000\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "a=rtpmap:", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "a=ptime:20\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "a=ptime:", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "a=fmtp:", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "a=sendrecv", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "t=0 0\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "v=0\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "s=-\r\n", pk, &k, &i);
 ts_add_str_templ_tag(&ts_templ_sip[i], "a=sendrecv\r\n", pk, &k, &i);
 
//Domains
 ts_add_str_templ_tag(&ts_templ_sip[i], ".com", pk, &k, &i);
 
 ts_templ_sip_count = i;
} /* init_ts_templ_sip */

void init_ts_templ_h323()
{	BYTE k = 0x00; //Key series start pos !
	BYTE pk = '~';
	int i=0; 
	ts_add_str_templ_tag(&ts_templ_h323[i], "H323-", pk, &k, &i);
        
	ts_templ_h323_count = i;
} /* init_ts_templ_h323 */

void init_ts_templ_ldap()
{	BYTE k = 0x00; //Key series start pos !
	BYTE pk = '~';
	int i=0; 
	ts_add_str_templ_tag(&ts_templ_ldap[i], "netlogon", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ldap[i], "Host", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ldap[i], "User", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ldap[i], "AAC", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ldap[i], "DomainGuid", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ldap[i], "NtVer", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ldap[i], "Netlogon", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ldap[i], "DnsDomain", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ldap[i], "LdapErr:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ldap[i], "comment:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ldap[i], "AcceptSecurityContext", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ldap[i], "error", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ldap[i], "data", pk, &k, &i);

	ts_templ_ldap_count = i;
} /* init_ts_templ_ldap */


void init_ts_templ_krb()
{	BYTE k = 0x00; //Key series start pos !
	BYTE pk = '~';
	int i=0; 
	ts_add_str_templ_tag(&ts_templ_krb[i], "", pk, &k, &i);
        
	ts_templ_krb_count = i;
} /* init_ts_templ_krb */

void init_ts_templ_smb()
{	BYTE k = 0x00; //Key series start pos !
	BYTE pk = '~';
	int i=0; 
	char binary_tag[60]; memset(binary_tag, 0x00, 60);
//	ts_add_str_templ_tag(&ts_templ_smb[i], "", pk, &k, &i);
	
	binary_tag[0]=0xff; binary_tag[1]='S'; binary_tag[2]='M'; binary_tag[3]='B';
	ts_add_bnry_templ_tag(&ts_templ_smb[i], binary_tag, 4, pk, &k, &i);
	
	binary_tag[0]=0x00; binary_tag[1]=0x00; binary_tag[2]=0x00; binary_tag[3]=0x00;
	ts_add_bnry_templ_tag(&ts_templ_smb[i], binary_tag, 4, pk, &k, &i);
	
	binary_tag[0]='S'; binary_tag[1]=0x00; binary_tag[2]='a'; binary_tag[3]=0x00;
	binary_tag[4]='m'; binary_tag[5]=0x00; binary_tag[6]='b'; binary_tag[7]=0x00;
	binary_tag[8]='a'; binary_tag[9]=0x00;
	ts_add_bnry_templ_tag(&ts_templ_smb[i], binary_tag, 10, pk, &k, &i);
	
	binary_tag[0]='U'; binary_tag[1]=0x00; binary_tag[2]='n'; binary_tag[3]=0x00;
	binary_tag[4]='i'; binary_tag[5]=0x00; binary_tag[6]='x'; binary_tag[7]=0x00;
	ts_add_bnry_templ_tag(&ts_templ_smb[i], binary_tag, 8, pk, &k, &i);
	
	binary_tag[0]='W'; binary_tag[1]=0x00; binary_tag[2]='i'; binary_tag[3]=0x00;
	binary_tag[4]='n'; binary_tag[5]=0x00; binary_tag[6]='d'; binary_tag[7]=0x00;
	binary_tag[8]='o'; binary_tag[9]=0x00; binary_tag[10]='w'; binary_tag[11]=0x00;
	binary_tag[12]='s'; binary_tag[13]=0x00;
	ts_add_bnry_templ_tag(&ts_templ_smb[i], binary_tag, 14, pk, &k, &i);
        
	ts_templ_smb_count = i;
   printk("TAGS: ts_templ_smb_count:%d - total:%d - free:%d\n", i, MAX_TS_TEMPL_SMB, MAX_TS_TEMPL_SMB-i);
} /* init_ts_templ_smb */

void init_ts_templ_ssdp()
{	BYTE k = 0x00; //Key series start pos !
	BYTE pk = '~';
	int i=0; 
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "M-SEARCH * HTTP/1.1\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "MX: 1\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "Mx: 15\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "Mx: ", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "St: urn:schemas-upnp-org:device:MediaRenderer:1\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "NTS:ssdp:byebye\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "NTS:ssdp:alive\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "NT:upnp:rootdevice\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "Cache-Control:max-age=1800\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "ST: upnp:rootdevice\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "St: upnp:rootdevice\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "HOST: 239.255.255.250:1900\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "Host: 239.255.255.250:1900\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "MAN: \"ssdp:discover\"\r\n\r\n", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "MAN: \"ssdp:discover\"\r\n", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ssdp[i], "Man: \"ssdp:discover\"\r\n", pk, &k, &i);
   
   ts_add_str_templ_tag(&ts_templ_ssdp[i], "Server:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "NTS:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "USN:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "Location:http://", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ssdp[i], "Location:", pk, &k, &i);
   
   
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "urn:schemas-upnp-org:device:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "urn:schemas-upnp-org:service:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "urn:schemas-", pk, &k, &i);
	
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "UPnP/1.0", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "UPnP-Device-Host/1.0", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "UPnP", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "http://", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "192.168.", pk, &k, &i);

   ts_add_str_templ_tag(&ts_templ_ssdp[i], "upnp:rootdevice", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ssdp[i], "upnp:", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ssdp[i], "upnp", pk, &k, &i);
   ts_add_str_templ_tag(&ts_templ_ssdp[i], "ssdp:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "ssdp", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "uuid:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "uuid", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "urn:", pk, &k, &i);
	ts_add_str_templ_tag(&ts_templ_ssdp[i], "urn", pk, &k, &i);
	
	ts_templ_ssdp_count = i;
   printk("TAGS: ts_templ_ssdp_count:%d - total:%d - free:%d\n", i, MAX_TS_TEMPL_SSDP, MAX_TS_TEMPL_SSDP-i);
} /* init_ts_templ_ssdp */

static void init_ts_dns_domains(void)
{ int i=0;
  for(i=0;i<MAX_DNS_DOMAINS;i++)
  { dns_domains[i].binary_domain_len=0;
	 dns_domains[i].en=TS_FALSE;
  }
}

void ts_init()
{ int i; //all loop index
 printk("@ ts_init() - start\n");
 
 ts_pkt_templ_large_dict = kmalloc( sizeof(ts_dict_t)* \
	(MAX_TS_HTTP_TEMPL_DICT + MAX_TS_TEMPL_SMTP + MAX_TS_TEMPL_SSH + \
	 MAX_TS_TEMPL_SSL + MAX_TS_TEMPL_POP + MAX_TS_TEMPL_MYSQL + \ 
	 MAX_TS_TEMPL_PGSQL + MAX_TS_TEMPL_MSSQL + MAX_TS_TEMPL_HTTP + \
	 MAX_TS_TEMPL_DNS + MAX_TS_TEMPL_TELNET + MAX_TS_TEMPL_IMAP + \ 
	 MAX_TS_TEMPL_MAPI + MAX_TS_TEMPL_FTP + MAX_TS_TEMPL_NFS + \ 
	 MAX_TS_TEMPL_ICA + MAX_TS_TEMPL_RDP +MAX_TS_TEMPL_SPICE + \
	 MAX_TS_TEMPL_VOIP + MAX_TS_TEMPL_SIP + MAX_TS_TEMPL_H323 + \ 
	 MAX_TS_PKT_TEMPL_COMMON + MAX_TS_TEMPL_GENERIC + MAX_TS_TEMPL_SQL + \
	 MAX_TS_TEMPL_LDAP + MAX_TS_TEMPL_KRB + MAX_TS_TEMPL_SMB + MAX_TS_TEMPL_SSDP ) , GFP_DMA|GFP_KERNEL);
 if(ts_pkt_templ_large_dict==NULL) printk("TS: ts_pkt_templ_large_dict - alloc_failed!\n");
 else 
 { printk("TS: ts_pkt_templ_large_dict - alloc success!\n");
	 ts_http_templ_dict=ts_pkt_templ_large_dict;  init_ts_http_templ_dict();
	 ts_templ_smtp=(ts_http_templ_dict+MAX_TS_HTTP_TEMPL_DICT); init_ts_templ_smtp();
	 ts_templ_ssh=(ts_templ_smtp+MAX_TS_TEMPL_SMTP); init_ts_templ_ssh();
	 ts_templ_ssl=(ts_templ_ssh+MAX_TS_TEMPL_SSH); init_ts_templ_ssl();
	 ts_templ_pop=(ts_templ_ssl+MAX_TS_TEMPL_SSL); init_ts_templ_pop();
	 ts_templ_mysql=(ts_templ_pop+MAX_TS_TEMPL_POP); init_ts_templ_mysql();
	 ts_templ_pgsql=(ts_templ_mysql+MAX_TS_TEMPL_MYSQL); init_ts_templ_pgsql();
	 ts_templ_mssql=(ts_templ_pgsql+MAX_TS_TEMPL_PGSQL); init_ts_templ_mssql();
	 ts_templ_http=(ts_templ_mssql+MAX_TS_TEMPL_MSSQL); init_ts_templ_http();
	 ts_templ_dns=(ts_templ_http+MAX_TS_TEMPL_HTTP); init_ts_templ_dns();
	 ts_templ_telnet=(ts_templ_dns+MAX_TS_TEMPL_DNS); init_ts_templ_telnet();
	 ts_templ_imap=(ts_templ_telnet+MAX_TS_TEMPL_TELNET); init_ts_templ_imap();
	 ts_templ_mapi=(ts_templ_imap+MAX_TS_TEMPL_IMAP); init_ts_templ_mapi();
	 ts_templ_ftp=(ts_templ_mapi+MAX_TS_TEMPL_MAPI); init_ts_templ_ftp();
	 ts_templ_nfs=(ts_templ_ftp+MAX_TS_TEMPL_FTP); init_ts_templ_nfs();
	 ts_templ_ica=(ts_templ_nfs+MAX_TS_TEMPL_NFS); init_ts_templ_ica();
	 ts_templ_rdp=(ts_templ_ica+MAX_TS_TEMPL_ICA); init_ts_templ_rdp();
	 ts_templ_spice=(ts_templ_rdp+MAX_TS_TEMPL_RDP); init_ts_templ_spice();
	 ts_templ_voip=(ts_templ_spice+MAX_TS_TEMPL_SPICE); init_ts_templ_voip();
	 ts_templ_sip=(ts_templ_voip+MAX_TS_TEMPL_VOIP); init_ts_templ_sip();
	 ts_templ_h323=(ts_templ_sip+MAX_TS_TEMPL_SIP); init_ts_templ_h323();
	 ts_templ_common=(ts_templ_sip+MAX_TS_TEMPL_H323); init_ts_templ_common();
	 ts_templ_generic=(ts_templ_common+MAX_TS_PKT_TEMPL_COMMON); init_ts_templ_generic();
	 ts_templ_sql=(ts_templ_generic+MAX_TS_TEMPL_GENERIC); init_ts_templ_sql();
	 ts_templ_ldap=(ts_templ_sql+MAX_TS_TEMPL_SQL); init_ts_templ_ldap();
	 ts_templ_krb=(ts_templ_ldap+MAX_TS_TEMPL_LDAP); init_ts_templ_krb();
	 ts_templ_smb=(ts_templ_krb+MAX_TS_TEMPL_KRB); init_ts_templ_smb();
	 ts_templ_ssdp=(ts_templ_smb+MAX_TS_TEMPL_SMB); init_ts_templ_ssdp();
 }

 dns_domains=kmalloc(sizeof(dns_domain_t)*MAX_DNS_DOMAINS, GFP_DMA|GFP_KERNEL); if(dns_domains==NULL) printk("TS: dns_domains - alloc_failed!\n"); else init_ts_dns_domains();
 http_access_logs=kmalloc(sizeof(http_access_log_t)*MAX_DPI_LOG_LINES, GFP_DMA|GFP_KERNEL); if(http_access_logs==NULL) printk("TS: http_access_logs - alloc_failed!\n"); else init_http_access_log_list();
 dns_request_logs=kmalloc(sizeof(dns_request_log_t)*MAX_DPI_LOG_LINES, GFP_DMA|GFP_KERNEL); if(dns_request_logs==NULL) printk("TS: dns_request_logs - alloc_failed!\n"); else init_dns_request_log_list();
 pop_logs=kmalloc(sizeof(pop_log_t)*MAX_DPI_LOG_LINES, GFP_DMA|GFP_KERNEL); if(pop_logs==NULL) printk("TS: pop_logs - alloc_failed!\n"); else ts_init_pop_log_list();
	
 ts_init_proc();
  
 init_timer(&ts_coal_ip_output_bkt_timer);
 init_timer(&ts_coal_ip_br_forward_bkt_timer);

 //do init_bucket everytime you use, since we only partially initialize here
 ts_clean_bucket(&ts_coal_ip_output_bkt);
 ts_clean_bucket(&ts_coal_ip_br_forward_bkt);

 memset(&ts_oper_stats, 0x00, sizeof(ts_stats_t));
 memset(&ts_coal_stats, 0x00, sizeof(ts_coal_stats_t));
 memset(&ts_lan_pkt_sizes_stats, 0x00, sizeof(ts_pkt_sizes_stats_t));
 memset(&ts_wan_pkt_sizes_stats, 0x00, sizeof(ts_pkt_sizes_stats_t));
 
 for(i=0;i<MAX_REMOTE_LIST;i++) { r_ip_ntwrk_list[i].en=r_ip_machine_list[i].en=TS_FALSE; }
 for(i=0;i<MAX_PKTMEM_LIST;i++) 
 { optmem[i].en=false;
 	optmem[i].buf = kmalloc( sizeof(BYTE)*(TS_MAX_OPT_BUF_LEN), GFP_DMA|GFP_KERNEL);
 	optmem[i].buf2 = kmalloc( sizeof(BYTE)*(TS_MAX_OPT_BUF_LEN), GFP_DMA|GFP_KERNEL);
 	optmem[i].wrkmem = kmalloc( sizeof(BYTE)*(TS_MAX_OPT_BUF_LEN), GFP_DMA|GFP_KERNEL);
 	///optmem[i].lz4hc_wrkmem = kmalloc( sizeof(BYTE)*(LZ4HC_MEM_COMPRESS), GFP_DMA|GFP_KERNEL);
 	optmem[i].lz4hc_wrkmem = kmalloc( sizeof(BYTE)*(LZO1X_1_MEM_COMPRESS), GFP_DMA|GFP_KERNEL);
 	
 	unoptmem[i].en=false;
 	unoptmem[i].buf = kmalloc( sizeof(BYTE)*(TS_MAX_OPT_BUF_LEN), GFP_DMA|GFP_KERNEL);
 	unoptmem[i].wrkmem = kmalloc( sizeof(BYTE)*(TS_MAX_OPT_BUF_LEN), GFP_DMA|GFP_KERNEL);
 }

 printk("@ ts_init() - end\n");
}
