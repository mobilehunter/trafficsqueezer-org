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
#ifndef _TS_PKT_TEMPLATING_H
#define _TS_PKT_TEMPLATING_H
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
#include <net/trafficsqueezer/comp.h>
#include <net/trafficsqueezer/skbuff.h>

#define KEY_LEN 2
typedef struct __ts_dict_t_ {
 BYTE txt[85]; //Max 85 bytes per text
 size_t txt_len;
 BYTE k[KEY_LEN];
}ts_dict_t;

extern ts_dict_t *ts_pkt_templ_large_dict; //one buffer which holds everything

#define MAX_TS_TEMPL_GENERIC 256
extern ts_dict_t *ts_templ_generic; extern int ts_templ_generic_count;

#define MAX_TS_PKT_TEMPL_COMMON 254
extern ts_dict_t *ts_templ_common; extern int ts_templ_common_count;

#define MAX_TS_TEMPL_HTTP 256
extern ts_dict_t *ts_templ_http; extern int ts_templ_http_count;

#define MAX_TS_TEMPL_DNS 220
extern ts_dict_t *ts_templ_dns; extern int ts_templ_dns_count;

#define MAX_TS_TEMPL_TELNET 60
extern ts_dict_t *ts_templ_telnet; extern int ts_templ_telnet_count;

#define MAX_TS_TEMPL_IMAP 70
extern ts_dict_t *ts_templ_imap; extern int ts_templ_imap_count;

#define MAX_TS_TEMPL_MAPI 40
extern ts_dict_t *ts_templ_mapi; extern int ts_templ_mapi_count;

#define MAX_TS_TEMPL_FTP 180
extern ts_dict_t *ts_templ_ftp; extern int ts_templ_ftp_count;

#define MAX_TS_TEMPL_NFS 170
extern ts_dict_t *ts_templ_nfs; extern int ts_templ_nfs_count;

#define MAX_TS_TEMPL_MYSQL 50
extern ts_dict_t *ts_templ_mysql; extern int ts_templ_mysql_count;

#define MAX_TS_TEMPL_PGSQL 50
extern ts_dict_t *ts_templ_pgsql; extern int ts_templ_pgsql_count;

#define MAX_TS_TEMPL_SQL 150
extern ts_dict_t *ts_templ_sql; extern int ts_templ_sql_count;

#define MAX_TS_TEMPL_MSSQL 100
extern ts_dict_t *ts_templ_mssql; extern int ts_templ_mssql_count;

#define MAX_TS_TEMPL_SSH 100
extern ts_dict_t *ts_templ_ssh; extern int ts_templ_ssh_count;

#define MAX_TS_TEMPL_SSL 150
extern ts_dict_t *ts_templ_ssl; extern int ts_templ_ssl_count;

#define MAX_TS_TEMPL_SMTP 40
extern ts_dict_t *ts_templ_smtp; extern int ts_templ_smtp_count;

#define MAX_TS_TEMPL_POP 150
extern ts_dict_t *ts_templ_pop; extern int ts_templ_pop_count;

#define MAX_TS_TEMPL_CIFS 220
extern ts_dict_t *ts_templ_cifs; extern int ts_templ_cifs_count;

#define MAX_TS_TEMPL_ICA 40
extern ts_dict_t *ts_templ_ica; extern int ts_templ_ica_count;

#define MAX_TS_TEMPL_RDP 220
extern ts_dict_t *ts_templ_rdp; extern int ts_templ_rdp_count;

#define MAX_TS_TEMPL_SPICE 60
extern ts_dict_t *ts_templ_spice; extern int ts_templ_spice_count;

#define MAX_TS_TEMPL_VOIP 120
extern ts_dict_t *ts_templ_voip; extern int ts_templ_voip_count;

#define MAX_TS_TEMPL_SIP 220
extern ts_dict_t *ts_templ_sip; extern int ts_templ_sip_count;

#define MAX_TS_TEMPL_H323 50
extern ts_dict_t *ts_templ_h323; extern int ts_templ_h323_count;

#define MAX_TS_TEMPL_LDAP 50
extern ts_dict_t *ts_templ_ldap; extern int ts_templ_ldap_count;

#define MAX_TS_TEMPL_KRB 50
extern ts_dict_t *ts_templ_krb; extern int ts_templ_krb_count;

#define MAX_TS_TEMPL_SMB 50
extern ts_dict_t *ts_templ_smb; extern int ts_templ_smb_count;

#define MAX_TS_TEMPL_SSDP 70
extern ts_dict_t *ts_templ_ssdp; extern int ts_templ_ssdp_count;

#define MAX_TS_HTTP_TEMPL_DICT 256
extern ts_dict_t *ts_http_templ_dict; extern int ts_http_templ_dict_count;

void ts_templ(BYTE *flag, BYTE *templ_id, BYTEx2 proto_port, BYTE *pbuff, size_t *pbuff_len, BYTE *wrkmem);
bool ts_untempl(BYTE templ_id, BYTE *pbuff, size_t *pbuff_len);
void ts_generic_templ(BYTE *flag, BYTE *pbuff, size_t *pbuff_len, BYTE *wrkmem);
bool ts_generic_untempl(BYTE *pbuff, size_t *pbuff_len);
void ts_common_templ(BYTE *flag, BYTE *pbuff, size_t *pbuff_len, BYTE *wrkmem);
bool ts_common_untempl(BYTE *pbuff, size_t *pbuff_len);
void ts_http_templ(BYTE *flag, BYTEx2 protocol_port, BYTE *pbuff, size_t *pbuff_len, BYTE *wrkmem);
bool ts_http_untempl(BYTE *pbuff, size_t *pbuff_len);
#endif