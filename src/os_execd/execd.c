#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef ARGV0
   #define ARGV0 "ossec-execd"
#endif

#include "headers/defs.h"
#include "headers/os_err.h"
#include "headers/mq_op.h"
#include "headers/sig_op.h"
#include "headers/debug_op.h"
#include "headers/help.h"
#include "headers/privsep_op.h"
#include "headers/file_op.h"

#include "os_regex/os_regex.h"
#include "os_net/os_net.h"

#include "error_messages/error_messages.h"

#include "execd.h"

/* Config function */    
int ExecConf(char *cfgfile, execd_config *execd);
/* Internal functions */
void OS_Run(int q, execd_config *execd);

short int dbg_flag=0;
short int chroot_flag=0;

int main(int argc, char **argv)
	{
	char c;
	int uid=0,gid=0,m_queue=0;
	char *dir  = DEFAULTDIR;
	char *user = EXECUSER;
	char *group = GROUPGLOBAL;
	char *cfg = DEFAULTCPATH;

	/* Mail Structure */
    execd_config execd;
	
	while((c = getopt(argc, argv, "dhu:g:D:c:")) != -1){
	   switch(c){
		case 'h':
		   help();
		   break;
		case 'd':
		   dbg_flag++;
		   break;
		case 'u':
		   if(!optarg)
			ErrorExit("%s: -u needs an argument",ARGV0);
		   user=optarg;
		   break;
		case 'g':
		   if(!optarg)
			   ErrorExit("%s: -g needs an argument",ARGV0);
		   group=optarg;
		   break;
		case 'D':
		   if(!optarg)
			   ErrorExit("%s: -D needs an argument",ARGV0);
		   dir=optarg;
		case 'c':
		   if(!optarg)
			   ErrorExit("%s: -c needs an argument",ARGV0);
		   cfg = optarg;
		   break;
		default:
		   help();
		   break;
	   }
                
	}

	/* Starting daemon */
	verbose(STARTED_MSG,ARGV0);
        
	/*Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
		ErrorExit(USER_ERROR,ARGV0,user,group);

	/* Reading configuration */
    {
        int rval=0;    
        if((rval = ExecConf(cfg,&execd)) < 0)
        {
            if(rval == OS_NOTFOUND)
            {
                exit(0);
            }
            ErrorExit(CONFIG_ERROR,ARGV0);
        }
    }
    
	/* Privilege separation */	
	if(Privsep_SetGroup(gid) < 0)
		ErrorExit(SETGID_ERROR,ARGV0,group);

    if(Privsep_Chroot(dir) < 0)
		ErrorExit(CHROOT_ERROR,ARGV0,dir);
	
	chroot_flag=1; /* Inside chroot now */

	/* Changing user */        
	if(Privsep_SetUser(uid) < 0)
		ErrorExit(SETUID_ERROR,ARGV0,user);

	/* verbose message .. */
	verbose(PRIVSEP_MSG,ARGV0,dir,user);

	/* Starting queue (exec queue) */
	if((m_queue = StartMQ(EXECQUEUE,READ)) < 0)
		ErrorExit(QUEUE_ERROR,ARGV0,EXECQUEUE);
	
	/* Signal manipulation */
	StartSIG(ARGV0);
	
	/* Forking and going to the background */
	if(dbg_flag == 0)
		{               
		int pid=0;
		if((pid = fork()) < 0)
		  ErrorExit(FORK_ERROR,ARGV0);
		else if(pid == 0)
		  {     
		  /* Creating the PID file */
		  if(CreatePID(ARGV0, getpid()) < 0)
		    ErrorExit(PID_ERROR,ARGV0);
		  }             
		else                    
		  exit(0);
		}

	/* the real daemon now */	
	OS_Run(m_queue,&execd);
	exit(0);
	}


/* OS_Run: Read the queue and send the appropriate alerts */
void OS_Run(int q, execd_config *execd)
	{
	ExecdMsg msg;
	
	while(1)
	  {
	  /* Receive message from queue */
	  if(OS_RecvExecQ(q, &msg) == 0)
	  	{
            /*
		//if(OS_Sendmail(mail,&msg) < 0)
		//   merror(SNDMAIL_ERROR,ARGV0,mail->smtpserver);
		//free(msg.body);
		//free(msg.subject);
		//msg.body=NULL;
		//msg.subject=NULL;	
        */
        OS_FreeExecdMsg(&msg);
	  	}
	  else
		merror(QUEUE_ERROR,ARGV0,EXECQUEUE);
	  }
	}

