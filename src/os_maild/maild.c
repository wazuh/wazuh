/*   $OSSEC, maild.c, v0.2, 2005/08/24, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* v0.2 (2005/08/24): Adding variable timeout
 * v0.1 (2005/03/15)
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef MAILD
   #define MAILD
#endif

#ifndef ARGV0
   #define ARGV0 "ossec-maild"
#endif

#include "headers/defs.h"
#include "headers/mq_op.h"
#include "headers/sig_op.h"
#include "headers/debug_op.h"
#include "headers/help.h"
#include "headers/privsep_op.h"
#include "headers/file_op.h"

#include "os_regex/os_regex.h"
#include "os_net/os_net.h"

#include "error_messages/error_messages.h"

#include "maild.h"
#include "mail_list.h"

short int dbg_flag=0;
short int chroot_flag=0;

void OS_Run(int q, MailConfig *mail);

int main(int argc, char **argv)
{
    char c;
    int uid=0,gid=0,m_queue=0;
    char *dir  = DEFAULTDIR;
    char *user = MAILUSER;
    char *group = GROUPGLOBAL;
    char *cfg = DEFAULTCPATH;

    /* Mail Structure */
    MailConfig mail;

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
    debug1(STARTED_MSG,ARGV0);

    /*Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
        ErrorExit(USER_ERROR,ARGV0,user,group);

    /* Reading configuration */
    if(MailConf(cfg, &mail) < 0)
        ErrorExit(CONFIG_ERROR,ARGV0);

    /* Privilege separation */	
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);

    if(Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR,ARGV0,dir);

    chroot_flag=1; /* Inside chroot now */

    /* Changing user */        
    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR,ARGV0,user);

    /* debug1 message .. */
    debug1(PRIVSEP_MSG,ARGV0,dir,user);

    /* Starting queue (mail queue) */
    if((m_queue = StartMQ(MAILQUEUE,READ)) < 0)
        ErrorExit(QUEUE_ERROR,ARGV0,MAILQUEUE);

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
    OS_Run(m_queue,&mail);
    exit(0);
}


/* OS_Run: Read the queue and send the appropriate alerts.
 * not supposed to return..
 */
void OS_Run(int q, MailConfig *mail)
{
    MailMsg *msg;

    time_t tm;     
    struct tm *p;       

    int mailsent = 0;
    int childcount = 0;
    int today = 0;		        
    int thishour = 0;

    /* Getting currently time before starting */
    tm = time(NULL);
    p = localtime(&tm);	
    today = p->tm_mday;
    thishour = p->tm_hour;

    /* Creating the list */
    OS_CreateMailList(MAIL_LIST_SIZE);    
 
    /* Setting default timeout */
    mail_timeout = DEFAULT_TIMEOUT;
    
    while(1)
    {
        tm = time(NULL);
        p = localtime(&tm);

        /* If mail_timeout == NEXTMAIL_TIMEOUT, we will try to get
         * more messages, before sending anything
         */
        if((mail_timeout == NEXTMAIL_TIMEOUT) && (p->tm_hour == thishour))
        {
            /* getting more messages */
        }
        
        /* Hour changed. Send all supressed mails */ 
        else if((mailsent < mail->maxperhour && mailsent != 0)||
                ((p->tm_hour != thishour)&&(childcount < MAXCHILDPROCESS)) )
        {
            MailNode *mailmsg;
            pid_t pid;

            /* Checking if we have anything to sent */
            mailmsg = OS_CheckLastMail();
            if(mailmsg == NULL)
            {
                /* dont fork in here */
                goto snd_check_hour;
            }

            pid = fork();
            if(pid < 0)
            {
                merror("%s: Fork error");
                continue;
            }
            else if (pid == 0)
            {
                if(OS_Sendmail(mail) < 0)
                    merror(SNDMAIL_ERROR,ARGV0,mail->smtpserver);
                
                exit(0);    
            }
          
            /* Cleaning the memory */
            mailmsg = OS_PopLastMail(); 
            do
            {
                FreeMail(mailmsg); 
                mailmsg = OS_PopLastMail();
            }while(mailmsg);
            
            childcount++; 

            
            snd_check_hour:
            
            /* If we sent everything */
            if(p->tm_hour != thishour)
            {
                thishour = p->tm_hour;    

                mailsent = 0;
            }
        }
        
        /* Receive message from queue */
        if((msg = OS_RecvMailQ(q)) != NULL)
        {
            OS_AddMailtoList(msg);

            /* Change timeout to see if any new message is coming shortly */
            mail_timeout = NEXTMAIL_TIMEOUT;   /* 5 seconds only */
        
        }
        else
        {
            mail_timeout = DEFAULT_TIMEOUT; /* Default timeout */
            mailsent++;
        }

        /* Waiting for the childs .. */
        while (childcount) 
        {
            int wp;
            wp = waitpid((pid_t) -1, NULL, WNOHANG);
            if (wp < 0)
                merror("%s: Waitpid error.");  

            /* if = 0, we still need to wait for the child process */    
            else if (wp == 0) 
                break;
            else
                childcount--;
        }
            
    }
}

/* EOF */
