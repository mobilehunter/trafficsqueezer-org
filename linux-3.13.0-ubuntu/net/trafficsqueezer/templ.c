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
#include <net/sock.h>
#include <net/checksum.h>
#include <linux/route.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <linux/ctype.h>
#include <linux/gfp.h>
#include <net/trafficsqueezer/core.h>
#include <net/trafficsqueezer/memreplace.h>
#include <net/trafficsqueezer/templ.h>

ts_dict_t *ts_pkt_templ_large_dict=NULL; EXPORT_SYMBOL(ts_pkt_templ_large_dict);

ts_dict_t *ts_templ_generic=NULL; EXPORT_SYMBOL(ts_templ_generic);
int ts_templ_generic_count=0; EXPORT_SYMBOL(ts_templ_generic_count);

ts_dict_t *ts_templ_common=NULL; EXPORT_SYMBOL(ts_templ_common);
int ts_templ_common_count=0; EXPORT_SYMBOL(ts_templ_common_count);

ts_dict_t *ts_templ_http=NULL; EXPORT_SYMBOL(ts_templ_http);
int ts_templ_http_count=0; EXPORT_SYMBOL(ts_templ_http_count);

ts_dict_t *ts_templ_dns=NULL; EXPORT_SYMBOL(ts_templ_dns);
int ts_templ_dns_count=0; EXPORT_SYMBOL(ts_templ_dns_count);

ts_dict_t *ts_templ_telnet=NULL; EXPORT_SYMBOL(ts_templ_telnet);
int ts_templ_telnet_count=0; EXPORT_SYMBOL(ts_templ_telnet_count);

ts_dict_t *ts_templ_imap=NULL; EXPORT_SYMBOL(ts_templ_imap);
int ts_templ_imap_count=0; EXPORT_SYMBOL(ts_templ_imap_count);

ts_dict_t *ts_templ_mapi=NULL; EXPORT_SYMBOL(ts_templ_mapi);
int ts_templ_mapi_count=0; EXPORT_SYMBOL(ts_templ_mapi_count);

ts_dict_t *ts_templ_ftp=NULL; EXPORT_SYMBOL(ts_templ_ftp);
int ts_templ_ftp_count=0; EXPORT_SYMBOL(ts_templ_ftp_count);

ts_dict_t *ts_templ_nfs=NULL; EXPORT_SYMBOL(ts_templ_nfs);
int ts_templ_nfs_count=0; EXPORT_SYMBOL(ts_templ_nfs_count);

ts_dict_t *ts_templ_mysql=NULL; EXPORT_SYMBOL(ts_templ_mysql);
int ts_templ_mysql_count=0; EXPORT_SYMBOL(ts_templ_mysql_count);

ts_dict_t *ts_templ_pgsql=NULL; EXPORT_SYMBOL(ts_templ_pgsql);
int ts_templ_pgsql_count=0; EXPORT_SYMBOL(ts_templ_pgsql_count);

ts_dict_t *ts_templ_sql=NULL; EXPORT_SYMBOL(ts_templ_sql);
int ts_templ_sql_count=0; EXPORT_SYMBOL(ts_templ_sql_count);

ts_dict_t *ts_templ_mssql=NULL; EXPORT_SYMBOL(ts_templ_mssql);
int ts_templ_mssql_count=0; EXPORT_SYMBOL(ts_templ_mssql_count);

ts_dict_t *ts_templ_ssh=NULL; EXPORT_SYMBOL(ts_templ_ssh);
int ts_templ_ssh_count=0; EXPORT_SYMBOL(ts_templ_ssh_count);

ts_dict_t *ts_templ_ssl=NULL; EXPORT_SYMBOL(ts_templ_ssl);
int ts_templ_ssl_count=0; EXPORT_SYMBOL(ts_templ_ssl_count);

ts_dict_t *ts_templ_smtp; EXPORT_SYMBOL(ts_templ_smtp);
int ts_templ_smtp_count=0; EXPORT_SYMBOL(ts_templ_smtp_count);

ts_dict_t *ts_templ_pop=NULL; EXPORT_SYMBOL(ts_templ_pop);
int ts_templ_pop_count=0; EXPORT_SYMBOL(ts_templ_pop_count);

ts_dict_t *ts_templ_cifs=NULL; EXPORT_SYMBOL(ts_templ_cifs);
int ts_templ_cifs_count=0; EXPORT_SYMBOL(ts_templ_cifs_count);

ts_dict_t *ts_templ_ica=NULL; EXPORT_SYMBOL(ts_templ_ica);
int ts_templ_ica_count=0; EXPORT_SYMBOL(ts_templ_ica_count);

ts_dict_t *ts_templ_rdp=NULL; EXPORT_SYMBOL(ts_templ_rdp);
int ts_templ_rdp_count=0; EXPORT_SYMBOL(ts_templ_rdp_count);

ts_dict_t *ts_templ_spice=NULL; EXPORT_SYMBOL(ts_templ_spice);
int ts_templ_spice_count=0; EXPORT_SYMBOL(ts_templ_spice_count);

ts_dict_t *ts_templ_voip=NULL; EXPORT_SYMBOL(ts_templ_voip);
int ts_templ_voip_count=0; EXPORT_SYMBOL(ts_templ_voip_count);

ts_dict_t *ts_templ_sip=NULL; EXPORT_SYMBOL(ts_templ_sip);
int ts_templ_sip_count=0; EXPORT_SYMBOL(ts_templ_sip_count);

ts_dict_t *ts_templ_h323=NULL; EXPORT_SYMBOL(ts_templ_h323);
int ts_templ_h323_count=0; EXPORT_SYMBOL(ts_templ_h323_count);

ts_dict_t *ts_templ_ldap=NULL; EXPORT_SYMBOL(ts_templ_ldap);
int ts_templ_ldap_count=0; EXPORT_SYMBOL(ts_templ_ldap_count);

ts_dict_t *ts_templ_krb=NULL; EXPORT_SYMBOL(ts_templ_krb);
int ts_templ_krb_count=0; EXPORT_SYMBOL(ts_templ_krb_count);

ts_dict_t *ts_templ_smb=NULL; EXPORT_SYMBOL(ts_templ_smb);
int ts_templ_smb_count=0; EXPORT_SYMBOL(ts_templ_smb_count);

ts_dict_t *ts_templ_ssdp=NULL; EXPORT_SYMBOL(ts_templ_ssdp);
int ts_templ_ssdp_count=0; EXPORT_SYMBOL(ts_templ_ssdp_count);

ts_dict_t *ts_http_templ_dict=NULL; EXPORT_SYMBOL(ts_http_templ_dict);
int ts_http_templ_dict_count=0; EXPORT_SYMBOL(ts_http_templ_dict_count);

BYTE templ_bnry_key[2]={'~', 0x00}, templ_bnry_key2[3]={'~', 0x01, 0x00};
BYTE templ_common_bnry_key[2]={0x08, 0x00}, templ_common_bnry_key2[3]={0x08, 0x01, 0x00};
BYTE templ_gnric_bnry_key[2]={0x07, 0x00}, templ_gnric_bnry_key2[3]={0x07, 0x01, 0x00};
BYTE templ_http_bnry_key[2]={'^', 0x00}, templ_http_bnry_key2[3]={'^', 0x01, 0x00};

static bool templ_tags(char *comment, BYTE *wrkmem, size_t *wrkmem_size, ts_dict_t *ts_templ_x, int ts_templ_x_count)
{	int i;
	size_t delta;
	BYTE *pos=NULL;
	for(i=0;i<ts_templ_x_count;i++)
	{  pos=(BYTE *)memchr((BYTE *)wrkmem, (int)ts_templ_x[i].txt[0], *wrkmem_size);
		if(pos==NULL) continue;
		delta = (*wrkmem_size)-(pos-wrkmem);
		if(!ts_memreplace(pos, &delta, ts_templ_x[i].txt, ts_templ_x[i].txt_len, ts_templ_x[i].k, KEY_LEN, SKIP_KEY)) { return false; }
		(*wrkmem_size) = (pos-wrkmem)+delta;
	}
	return true;
}

void ts_templ(BYTE *flag, BYTE *templ_id, BYTEx2 proto_port, BYTE *pbuff, size_t *pbuff_len, BYTE *wrkmem)
{
	size_t wrkmem_size = 0;
	size_t __pbuff_len = (*pbuff_len);
	BYTE __templ_id = 0x00;

   memcpy((BYTE *)wrkmem, (BYTE *)pbuff, (size_t)__pbuff_len); wrkmem_size=__pbuff_len;
	if(!ts_memreplace(wrkmem, &wrkmem_size, templ_bnry_key, 1, templ_bnry_key2, KEY_LEN, NO_SKIP_KEY)) { return; }
	
	if(proto_port==PROTO_HTTP||proto_port==PROTO_SQUID) { if(!templ_tags("HTTP/SQUID", wrkmem, &wrkmem_size, ts_templ_http, ts_templ_http_count)) return; else __templ_id=PROTO_ID_HTTP; }
	else if(proto_port==PROTO_DNS) { if(!templ_tags("DNS", wrkmem, &wrkmem_size, ts_templ_dns, ts_templ_dns_count)) return; else __templ_id=PROTO_ID_DNS; }
	else if(proto_port==PROTO_TELNET) { if(!templ_tags("TELNET", wrkmem, &wrkmem_size, ts_templ_telnet, ts_templ_telnet_count)) return; else __templ_id=PROTO_ID_TELNET; }
	else if(proto_port==PROTO_IMAP||proto_port==PROTO_IMAPS) { if(!templ_tags("IMAP/IMAPS", wrkmem, &wrkmem_size, ts_templ_imap, ts_templ_imap_count)) return; else __templ_id=PROTO_ID_IMAP; }
	else if(proto_port==PROTO_FTP) { if(!templ_tags("FTP", wrkmem, &wrkmem_size, ts_templ_ftp, ts_templ_ftp_count)) return; else __templ_id=PROTO_ID_FTP; }
	else if(proto_port==PROTO_MYSQL)
	{ if(!templ_tags("MYSQL", wrkmem, &wrkmem_size, ts_templ_mysql, ts_templ_mysql_count)) return;
	  if(!templ_tags("SQL", wrkmem, &wrkmem_size, ts_templ_sql, ts_templ_sql_count)) return;
	  __templ_id=PROTO_ID_MYSQL;
	}
	else if(proto_port==PROTO_PGSQL)
	{ if(!templ_tags("PGSQL", wrkmem, &wrkmem_size, ts_templ_pgsql, ts_templ_pgsql_count)) return;
	  if(!templ_tags("SQL", wrkmem, &wrkmem_size, ts_templ_sql, ts_templ_sql_count)) return;
	  __templ_id=PROTO_ID_PGSQL;
	}
	else if(proto_port==PROTO_SMTP) { if(!templ_tags("SMTP", wrkmem, &wrkmem_size, ts_templ_smtp, ts_templ_smtp_count)) return; else __templ_id=PROTO_ID_SMTP; }
	else if(proto_port==PROTO_SSH) { if(!templ_tags("SSH", wrkmem, &wrkmem_size, ts_templ_ssh, ts_templ_ssh_count)) return; else __templ_id=PROTO_ID_SSH; }
	else if(proto_port==PROTO_SSL) { if(!templ_tags("SSL", wrkmem, &wrkmem_size, ts_templ_ssl, ts_templ_ssl_count)) return; else __templ_id=PROTO_ID_SSL; }
	else if(proto_port==PROTO_POP) { if(!templ_tags("POP", wrkmem, &wrkmem_size, ts_templ_pop, ts_templ_pop_count)) return; else __templ_id=PROTO_ID_HTTP; }
	else if(proto_port==PROTO_LDAP) { if(!templ_tags("LDAP", wrkmem, &wrkmem_size, ts_templ_ldap, ts_templ_ldap_count)) return; else __templ_id=PROTO_ID_LDAP; }
	else if(proto_port==PROTO_SIP||proto_port==PROTO_SIP2) { if(!templ_tags("SIP", wrkmem, &wrkmem_size, ts_templ_sip, ts_templ_sip_count)) return; else __templ_id=PROTO_ID_SIP; }
	else if(proto_port==PROTO_SMB) { if(!templ_tags("SMB", wrkmem, &wrkmem_size, ts_templ_smb, ts_templ_smb_count)) return; else __templ_id=PROTO_ID_SMB; }
	else if(proto_port==PROTO_SSDP) { if(!templ_tags("SSDP", wrkmem, &wrkmem_size, ts_templ_ssdp, ts_templ_ssdp_count)) return; else __templ_id=PROTO_ID_SSDP; }
	
	if(((wrkmem_size+TS_FLAG_SIZE) < __pbuff_len) && (wrkmem_size!=0))
	{ memcpy((BYTE *)pbuff, (BYTE *)wrkmem, (size_t)wrkmem_size); (*pbuff_len)=wrkmem_size;
	  (*flag) |= TS_FLAG_TEMPL;
	  (*templ_id) = __templ_id;
	  #ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
	  printk("templ_tags - prossd [wrkmem_size: %zu] [templ_id: %d] [flag: %d]\n", wrkmem_size, (*templ_id), *flag);
	  #endif 
	}
}

static bool untempl_tags(char *comment, BYTE *wrkmem, size_t *wrkmem_size, ts_dict_t *ts_templ_x, int ts_templ_x_count)
{	int i;
	size_t delta;
	BYTE *pos=NULL;
   for(i=(ts_templ_x_count-1);i>=0;i--)
	{
		pos=(BYTE *)memchr((BYTE *)wrkmem, (int)ts_templ_x[i].k[0], *wrkmem_size);
		if(pos==NULL) break;
		delta = (*wrkmem_size)-(pos-wrkmem);
				
		if(!ts_memreplace( pos, &delta, ts_templ_x[i].k, KEY_LEN, ts_templ_x[i].txt, ts_templ_x[i].txt_len, NO_SKIP_KEY)) { return false; }
		(*wrkmem_size) = (pos-wrkmem)+delta;
	}
	return true;
}

bool ts_untempl(BYTE templ_id, BYTE *pbuff, size_t *pbuff_len)
{   
	if(templ_id==PROTO_ID_SSDP) { if(!untempl_tags("SSDP", pbuff, pbuff_len, ts_templ_ssdp, ts_templ_ssdp_count)) { return false; }}   
   else if(templ_id==PROTO_ID_SMB) { if(!untempl_tags("SMB", pbuff, pbuff_len, ts_templ_smb, ts_templ_smb_count)) { return false; }}
	else if(templ_id==PROTO_ID_SIP||templ_id==PROTO_ID_SIP2) { if(!untempl_tags("SIP", pbuff, pbuff_len, ts_templ_sip, ts_templ_sip_count)) { return false; }}
   else if(templ_id==PROTO_ID_LDAP) { if(!untempl_tags("LDAP", pbuff, pbuff_len, ts_templ_ldap, ts_templ_ldap_count)) { return false; }}
   else if(templ_id==PROTO_ID_POP) { if(!untempl_tags("POP", pbuff, pbuff_len, ts_templ_pop, ts_templ_pop_count)) { return false; }}
   else if(templ_id==PROTO_ID_SSL) { if(!untempl_tags("SSL", pbuff, pbuff_len, ts_templ_ssl, ts_templ_ssl_count)) { return false; }}
   else if(templ_id==PROTO_ID_SSH) { if(!untempl_tags("SSH", pbuff, pbuff_len, ts_templ_ssh, ts_templ_ssh_count)) { return false; }}
   else if(templ_id==PROTO_ID_SMTP) { if(!untempl_tags("SMTP", pbuff, pbuff_len, ts_templ_smtp, ts_templ_smtp_count)) { return false; }}
   else if(templ_id==PROTO_ID_PGSQL) 
   { if(!untempl_tags("SQL", pbuff, pbuff_len, ts_templ_sql, ts_templ_sql_count)) { return false; }
     if(!untempl_tags("PGSQL", pbuff, pbuff_len, ts_templ_pgsql, ts_templ_pgsql_count)) { return false; }
	}
	else if(templ_id==PROTO_ID_MYSQL)
	{ if(!untempl_tags("SQL", pbuff, pbuff_len, ts_templ_sql, ts_templ_sql_count)) { return false; }
	  if(!untempl_tags("MYSQL", pbuff, pbuff_len, ts_templ_mysql, ts_templ_mysql_count)) { return false; }
	}
	else if(templ_id==PROTO_ID_FTP) { if(!untempl_tags("FTP", pbuff, pbuff_len, ts_templ_ftp, ts_templ_ftp_count)) { return false; }}
	else if(templ_id==PROTO_ID_IMAP||templ_id==PROTO_ID_IMAPS) { if(!untempl_tags("IMAP/IMAPS", pbuff, pbuff_len, ts_templ_imap, ts_templ_imap_count)) { return false; }}
	else if(templ_id==PROTO_ID_TELNET) { if(!untempl_tags("TELNET", pbuff, pbuff_len, ts_templ_telnet, ts_templ_telnet_count)) { return false; }}
	else if(templ_id==PROTO_ID_DNS) { if(!untempl_tags("DNS", pbuff, pbuff_len, ts_templ_dns, ts_templ_dns_count)) { return false; }}
	else if(templ_id==PROTO_ID_HTTP||templ_id==PROTO_ID_SQUID) { if(!untempl_tags("HTTP/SQUID", pbuff, pbuff_len, ts_templ_http, ts_templ_http_count)) { return false; }}

	if(!ts_memreplace( pbuff, pbuff_len, templ_bnry_key2, KEY_LEN, templ_bnry_key, 1, NO_SKIP_KEY)) { return false; }
	#ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
	printk("untempl_tags - prossd [pbuff_len: %zu]\n", *pbuff_len);
	#endif
   return true;
}

void ts_generic_templ(BYTE *flag, BYTE *pbuff, size_t *pbuff_len, BYTE *wrkmem)
{	size_t wrkmem_size = 0;
	size_t __pbuff_len = (*pbuff_len);
    
   memcpy((BYTE *)wrkmem, (BYTE *)pbuff, __pbuff_len); wrkmem_size=__pbuff_len;
	if(!ts_memreplace(wrkmem, &wrkmem_size, templ_gnric_bnry_key, 1, templ_gnric_bnry_key2, KEY_LEN, NO_SKIP_KEY)) { return; }
	if(templ_tags("generic", wrkmem, &wrkmem_size, ts_templ_generic, ts_templ_generic_count)==TS_ERROR) return;
	if( ((wrkmem_size+TS_FLAG_SIZE+5) < __pbuff_len) && (wrkmem_size!=0))
	{	memcpy( (BYTE *)pbuff, (BYTE *)wrkmem, wrkmem_size); (*pbuff_len)=wrkmem_size; (*flag) |= TS_FLAG_TEMPL_GENERIC;
		#ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
	  	printk("templ_tags - prossd [generic] [wrkmem_size: %zu] [flag: %d]\n", wrkmem_size, *flag);
	  	#endif 
	}
}

bool ts_generic_untempl(BYTE *pbuff, size_t *pbuff_len)
{	        	
	if(!untempl_tags("generic", pbuff, pbuff_len, ts_templ_generic, ts_templ_generic_count)) { return false; }
	if(!ts_memreplace(pbuff, pbuff_len, templ_gnric_bnry_key2, KEY_LEN, templ_gnric_bnry_key, 1, NO_SKIP_KEY)) { return false; }
   #ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
	printk("untempl_tags - prossd [generic] [pbuff_len: %zu]\n", *pbuff_len);
	#endif
   return true;
}

void ts_common_templ(BYTE *flag, BYTE *pbuff, size_t *pbuff_len, BYTE *wrkmem)
{	size_t wrkmem_size = 0;
	size_t __pbuff_len = (*pbuff_len);

   memcpy( (BYTE *)wrkmem, (BYTE *)pbuff, __pbuff_len); wrkmem_size=__pbuff_len;
	if(!ts_memreplace(wrkmem, &wrkmem_size, templ_common_bnry_key, 1, templ_common_bnry_key2, KEY_LEN, NO_SKIP_KEY)) { return; }
	if(templ_tags("common", wrkmem, &wrkmem_size, ts_templ_common, ts_templ_common_count)==TS_ERROR) return;
	if( ((wrkmem_size+TS_FLAG_SIZE+5) < __pbuff_len) && (wrkmem_size!=0))
	{	memcpy( (BYTE *)pbuff, (BYTE *)wrkmem, wrkmem_size); (*pbuff_len)=wrkmem_size; (*flag) |= TS_FLAG_TEMPL_COMMON;
		#ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
	  	printk("templ_tags - prossd [common] [wrkmem_size: %zu] [flag: %d]\n", wrkmem_size, *flag);
	  	#endif
	}
}

bool ts_common_untempl(BYTE *pbuff, size_t *pbuff_len)
{  	   
	if(!untempl_tags("common", pbuff, pbuff_len, ts_templ_common, ts_templ_common_count)) { return false; }
	if(!ts_memreplace(pbuff, pbuff_len, templ_common_bnry_key2, KEY_LEN, templ_common_bnry_key, 1, NO_SKIP_KEY)) { return false; }
	#ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
	printk("untempl_tags - prossd [common] [pbuff_len: %zu]\n", *pbuff_len);
	#endif
  return true;
}

void ts_http_templ(BYTE *flag, BYTEx2 proto_port, BYTE *pbuff, size_t *pbuff_len, BYTE *wrkmem)
{	size_t wrkmem_size = 0;
	size_t __pbuff_len = (*pbuff_len);
	if((proto_port!=PROTO_HTTP) && (proto_port!=PROTO_SQUID)) return TS_FALSE;
    
   memcpy((BYTE *)wrkmem, (BYTE *)pbuff, __pbuff_len); wrkmem_size=__pbuff_len;
	if(!ts_memreplace(wrkmem, &wrkmem_size, templ_http_bnry_key, 1, templ_http_bnry_key2, KEY_LEN, NO_SKIP_KEY)) { return; }
	if(templ_tags("http-opt", wrkmem, &wrkmem_size, ts_http_templ_dict, ts_http_templ_dict_count)==TS_ERROR) return;
	if( ((wrkmem_size+TS_FLAG_SIZE) < __pbuff_len) && (wrkmem_size!=0))
	{ memcpy((BYTE *)pbuff, (BYTE *)wrkmem, wrkmem_size); (*pbuff_len)=wrkmem_size; (*flag) |= TS_FLAG_HTTP;
	  #ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
	  printk("templ_tags - prossd [HTTP-OPT] [wrkmem_size: %zu] [flag: %d]\n", wrkmem_size, *flag);
	  #endif
	}
}

bool ts_http_untempl(BYTE *pbuff, size_t *pbuff_len)
{		
	if(!untempl_tags("http-opt", pbuff, pbuff_len, ts_http_templ_dict, ts_http_templ_dict_count)) { return false; }		
	if(!ts_memreplace(pbuff, pbuff_len, templ_http_bnry_key2, KEY_LEN, templ_http_bnry_key, 1, NO_SKIP_KEY)) { return false; }
	#ifdef CONFIG_TRAFFICSQUEEZER_DEBUG
	printk("untempl_tags - prossd [HTTP-OPT] [pbuff_len: %zu]\n", *pbuff_len);
	#endif
   return true;
}