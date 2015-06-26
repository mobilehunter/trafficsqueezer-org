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
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <asm/types.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <assert.h>
#include "../inc/core.h"
#include "../inc/udp.h"

int ts_udp_server_sock 			= 0;
BYTEx2 ts_udp_server_port 		= TS_UDP_SERVER_PORT;
struct sockaddr_in ts_udp_server_servaddr;
struct sockaddr_in ts_udp_server_cliaddr;

pthread_t udp_thread;
pthread_t generic_stats_thread;
pthread_t generic_25_sec_thread;
pthread_t generic_5_sec_thread;
pthread_t generic_consolidate_thread;

void *generic_stats_thread_start(void *a)
{
  while(TRUE)
  {
     system("php -f /var/www/html/php/stats_load_stats.php");
     sleep(30);
  }
}

void *generic_consolidate_thread_start(void *a)
{
  while(TRUE)
  {
     system("php -f /var/www/html/php/stats_consolidate_stats.php");
     sleep(800); //once in 13-14 hours (almost 2 times a day a bit more than that)
  }
}


void *generic_25_sec_thread_start(void *a)
{
  while(TRUE)
  {
     system("php -f /var/www/html/php/stats_dpi_load_dns_logs.php");
	  system("php -f /var/www/html/php/stats_dpi_load_pop_logs.php");
	  system("php -f /var/www/html/php/stats_dpi_load_http_access_logs.php");
     system("php -f /var/www/html/php/db_execute_command_output.php &");
     system("php -f /var/www/html/php/db_fill_port_list.php");
     system("php -f /var/www/html/php/db_load_nameserver.php");
     sleep(25);
  }
}

void *generic_5_sec_thread_start(void *a)
{
  while(TRUE)
  {
     system("php -f /var/www/html/php/db_to_kernel_jobs_push.php");
     system("php -f /var/www/html/php/db_execute_gui_jobs.php");
     sleep(5);
  }
}

int exit_main()
{
  ts_stop_udp_server();
  remove("/var/ts_pid");
  remove("/tmp/trafficsqueezerd.lock");
  exit(1);
}

#define RUNNING_DIR  "/tmp"
#define LOCK_FILE    "trafficsqueezerd.lock"
#define LOG_FILE     "/var/log/trafficsqueezerd.log"

void signal_handler(int sig) { printf("\nAborted\n\n"); exit_main(); }

void daemonize()
{
  int i,lfp;
  char str[20];
  if(getppid()==1) return;
  i=fork();
  if (i<0) exit(1);
  if (i>0) exit(0);
  setsid();
  for (i=getdtablesize();i>=0;--i) close(i);
  i=open("/dev/null",O_RDWR); dup(i); dup(i);
  umask(027);
  chdir(RUNNING_DIR);
  lfp=open(LOCK_FILE,O_RDWR|O_CREAT,0640);
  if (lfp<0) exit(1);
  if (lockf(lfp,F_TLOCK,0)<0) exit(0);
  sprintf(str,"%d\n",getpid());
  write(lfp,str,strlen(str));
  signal(SIGCHLD,SIG_IGN);
  signal(SIGTSTP,SIG_IGN);
  signal(SIGTTOU,SIG_IGN);
  signal(SIGTTIN,SIG_IGN);
}

int main( int argc, char ** argv )
{ int __no_daemon = FALSE;
  int i=0;
  
  if(argc>=2)
  {
	for(i=1; i<argc; i++)
	{
      if(!strcmp(argv[i],"--no-daemon"))
	   {	__no_daemon = TRUE;
	     	printf("\nTrafficSqueezer Daemon executing in NON Daemon mode !\n\n");
		}
		else if(!strcmp(argv[i],"--help"))
		{ printf("\nTrafficSqueezer - Daemon optional command line parameters:\n");
		  printf("  --help (or) -?  - Display this help and exit\n");
  		  printf("  --no-daemon - foreground mode\n\n");
  		  return TRUE; 
  		}
	}
  }
  
  if(__no_daemon==FALSE) { daemonize(); }

  ts_save_pid_file();  

  signal(SIGHUP,signal_handler);
  signal(SIGTERM,signal_handler);
  signal(SIGKILL,signal_handler);
  signal(SIGSTOP,signal_handler);
  signal(SIGINT,signal_handler);	

  for(i=0;i<12;i++) { printf("Initial sleep: Sleeping 6 seconds [%d]!\n", i); sleep(6); }

  system("php -f /var/www/html/php/db_to_kernel_config_push.php");
  system("php -f /var/www/html/php/db_to_file_tcp_optimize_config_push.php");
  system("php -f /var/www/html/php/db_to_system_static_network_route_table_push.php");
  system("php -f /var/www/html/php/db_to_system_forward_rule_iptables_push.php");
  system("php -f /var/www/html/php/nameserver_load_db.php");
  system("php -f /var/www/html/php/stats_consolidate_stats.php");
  
  pthread_create(&udp_thread, NULL, udp_thread_start, NULL);
  pthread_create(&generic_stats_thread, NULL, generic_stats_thread_start, NULL);
  pthread_create(&generic_consolidate_thread, NULL, generic_consolidate_thread_start, NULL);
  pthread_create(&generic_25_sec_thread, NULL, generic_25_sec_thread_start, NULL);
  pthread_create(&generic_5_sec_thread, NULL, generic_5_sec_thread_start, NULL);
  pthread_join(udp_thread, NULL);

  return TRUE;
}