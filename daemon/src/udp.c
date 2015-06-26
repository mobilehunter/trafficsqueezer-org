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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include "../inc/udp.h"
#include "../inc/core.h"

extern int ts_udp_server_sock;
extern BYTEx2 ts_udp_server_port;

extern struct sockaddr_in ts_udp_server_servaddr; 
extern struct sockaddr_in ts_udp_server_cliaddr;

BYTE udp_reply_buff[MAX_REPLY_BUFFER_SIZE]; //Reply to client UDP
size_t udp_reply_buff_len;
                                
static int ts_execute_udp_command(BYTE *command_buff, size_t command_len);

static int ts_start_udp_server()
{
	ts_udp_server_sock = socket(AF_INET,SOCK_DGRAM,0);
	if(ts_udp_server_sock<=0) return FALSE;

	bzero(&ts_udp_server_servaddr, sizeof(ts_udp_server_servaddr));
	ts_udp_server_servaddr.sin_family = AF_INET;
	ts_udp_server_servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	ts_udp_server_servaddr.sin_port=htons(ts_udp_server_port);
	bind( ts_udp_server_sock, (struct sockaddr *)&ts_udp_server_servaddr, sizeof(ts_udp_server_servaddr));
	return TRUE;
}

void *udp_thread_start(void *a)
{	 BYTE command_buff[2000];
    ts_start_udp_server();
    while(TRUE)
    {	
    	usleep(30);
		ts_receive_udp_command(command_buff);
    }
}

int ts_stop_udp_server()
{	if(ts_udp_server_sock>0) close(ts_udp_server_sock);
	return TRUE;
}

int ts_execute_system_command(BYTE *result_buff, size_t *result_len, BYTE *command, size_t command_len)
{
	BYTE temp[2000];
	strcpy(result_buff, "");
	sprintf(temp, "%s 2> /dev/null > /dev/null &", command);
	system(temp);
	*result_len = strlen( result_buff);
	return TRUE;
} /* ts_execute_system_command */


//Receive the command to be executed from the remote machine
//   execute the same in the local machine and send the status response SUCCESS/FAILURE
//   Flow: Fn. called from Server
int ts_receive_udp_command(BYTE *command_buff)
{
	//int status;
	int result = 0;
	size_t command_len;
	socklen_t len;
	bzero(command_buff, 2000);
	
	len = sizeof(ts_udp_server_cliaddr);
	result = recvfrom( ts_udp_server_sock, command_buff, 2000, 0,(struct sockaddr *)&ts_udp_server_cliaddr, &len);
			
	if(result>0)
	{	command_len = result;
		if(!strncmp((char *)command_buff,"system ", 7))
   	{
     		int execute_system_command_offset = 7;
     		ts_execute_system_command(udp_reply_buff, &udp_reply_buff_len, (command_buff+execute_system_command_offset), (size_t)(command_len-execute_system_command_offset) );
     		sendto(ts_udp_server_sock, udp_reply_buff, udp_reply_buff_len, 0,(struct sockaddr *)&ts_udp_server_cliaddr, sizeof(ts_udp_server_cliaddr));
   	}
 	}

	return TRUE;
}
