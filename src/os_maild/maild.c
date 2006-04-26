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

#ifndef MAILD
   #define MAILD
#endif

#ifndef ARGV0
   #define ARGV0 "ossec-maild"
#endif

#include "shared.h"
#include "maild.h"
#include "mail_list.h"


void OS_Run(MailConfig *mail);

int main(int argc, char **argv)
{
    int c, test_config = 0;
    int uid=0,gid=0;
    char *dir  = DEFAULTDIR;
    char *user = MAILUSER;
    char *group = GROUPGLOBAL;
    char *cfg = DEFAULTCPATH;

    /* Mail Structure */
    MailConfig mail;


    /* Setting the name */
    OS_SetName(ARGV0);
        

    while((c = getopt(argc, argv, "dhtu:g:D:c:")) != -1){
        switch(c){
            case 'h':
                help();
                break;
            case 'd':
                nowDebug();
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
            case 't':
                test_config = 1;    
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

    /* Exit here if test config is set */
    if(test_config)
        exit(0);
        
    /* Going on daemon mode */
    nowDaemon();
    goDaemon();

    
    /* Privilege separation */	
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);

    
    /* chrooting */
    if(Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR,ARGV0,dir);

    nowChroot();


    
    /* Changing user */        
    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR,ARGV0,user);


    debug1(PRIVSEP_MSG,ARGV0,dir,user);



    /* Signal manipulation */
    StartSIG(ARGV0);

    

    /* Creating PID files */
    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR,ARGV0);

    
    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, getpid());
    

    /* the real daemon now */	
    OS_Run(&mail);
    exit(0);
}


/* OS_Run: Read the queue and send the appropriate alerts.
 * not supposed to return..
 */
void OS_Run(MailConfig *mail)
{
    MailMsg *msg;

    time_t tm;     
    struct tm *p;       

    int mailsent = 0;
    int childcount = 0;
    int today = 0;		        
    int thishour = 0;

    file_queue *fileq;


    /* Getting currently time before starting */
    tm = time(NULL);
    p = localtime(&tm);	
    today = p->tm_mday;
    thishour = p->tm_hour;


    /* Init file queue */
    os_calloc(1, sizeof(file_queue), fileq);
    Init_FileQueue(fileq, p);


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
        else if(((mailsent < mail->maxperhour) && (mailsent != 0))||
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
                merror(FORK_ERROR, ARGV0);
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
        if((msg = OS_RecvMailQ(fileq, p)) != NULL)
        {
            OS_AddMailtoList(msg);
            
            /* Change timeout to see if any new message is coming shortly */
            mail_timeout = NEXTMAIL_TIMEOUT;   /* 5 seconds only */
        
        }
        else
        {
            if(mail_timeout == NEXTMAIL_TIMEOUT)
                mailsent++;
            
            mail_timeout = DEFAULT_TIMEOUT; /* Default timeout */
        }

        /* Waiting for the childs .. */
        while (childcount) 
        {
            int wp;
            wp = waitpid((pid_t) -1, NULL, WNOHANG);
            if (wp < 0)
                merror(WAITPID_ERROR, ARGV0);  

            /* if = 0, we still need to wait for the child process */    
            else if (wp == 0) 
                break;
            else
                childcount--;
        }
            
    }
}

/* EOF */
