/*   $OSSEC, remoted.c, v0.3, 2005/02/09, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* remote daemon.
 * Listen to remote packets and forward them to the analysis 
 * system
 */


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>  
#include <arpa/inet.h>

#include "os_net/os_net.h"

#ifndef ARGV0
   #define ARGV0 "ossec-remoted"
#endif

#include "remoted.h"

#include "headers/defs.h"
#include "headers/mq_op.h"
#include "headers/debug_op.h"
#include "headers/sig_op.h"
#include "headers/help.h"
#include "headers/privsep_op.h"
#include "headers/file_op.h"
#include "headers/sec.h"

#define IPSIZE 16

short int dbg_flag=0;
short int chroot_flag=0;

/* Error messages */
#include "error_messages/error_messages.h"



/* OS_IPNotAllowed, v0.1, 2005/02/11 
 * Checks if an IP is not allowed.
 */
int OS_IPNotAllowed(char *srcip, remoted *logr)
{
    if(logr->denyips != NULL)
    {
        int i=0;
        for(i=0;i<255;i++) /* Maximum access-list */
        {
            if(logr->denyips[i] == NULL)
                break;
            if(strncmp(logr->denyips[i],srcip,strlen(logr->denyips[i]))==0)
                return(1);
        }
    }
    if(logr->allowips != NULL)
    {
        int i=0;
        for(i=0;i<255;i++) /* Maximum access-list */
        {
            if(logr->allowips[i] == NULL)
                break;
            if(strncmp(logr->allowips[i],srcip,
                        strlen(logr->allowips[i]))==0)
                return(0);
        }
    }

    /* If the io is not allowed, it will be denied */
    return(1);
}


/* _startit v0.1, 2004/7/30
 * Internal Function. Does all the socket/ queueing
 * manipulation.
 * Maximum allowed input is 1024 bytes.
 */
void _startit(int position,int connection_type, int uid, 
              int gid, char *dir, remoted *logr)
{
    int sock;
    int m_queue;
    
    char *buffer;
    char srcip[IPSIZE];
    
    int port = 0;
    int _local_err = 0;
    
    keystruct keys;


    /* if SYSLOG and allowips is not defined, exit */
    if((logr->allowips == NULL)&&(connection_type == SYSLOG_CONN))
    {
        ErrorExit("%s: No ip/network allowed in the access list "
                  "for syslog. No reason for running it. Exiting...",
                  ARGV0);
    }
           
    if((logr->port == NULL)||(logr->port[position] == NULL)||
            ((port = atoi(logr->port[position])) <= 0) ||
              (port > 65535))
    {
        if(port < 0 || port > 65535)
            merror(PORT_ERROR,ARGV0,port);
            
        if(connection_type == SECURE_CONN)
            port = DEFAULT_SECURE;
            
        else if(connection_type == SYSLOG_CONN)
            port = DEFAULT_SYSLOG;
    }

    /* Only using UDP 
     * UDP is faster and unreliable. Perfect :)
     */	
    if((sock = OS_Bindportudp(port,NULL)) < 0)
        ErrorExit(BIND_ERROR,ARGV0,port);

    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,gid);

    if(Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR,ARGV0,dir);

    chroot_flag=1; /* Inside chroot now */

    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR,ARGV0, uid);

    /* Try three times to connect to the message queue.
     * Exit if all attempts fail.
     */
    if((m_queue = StartMQ(DEFAULTQUEUE,WRITE)) < 0)
    {	
        merror(QUEUE_ERROR,ARGV0, DEFAULTQUEUE);
        sleep(5);
        if((m_queue = StartMQ(DEFAULTQUEUE,WRITE)) < 0)
        {
            merror(QUEUE_ERROR,ARGV0, DEFAULTQUEUE);
            sleep(10);
            if((m_queue = StartMQ(DEFAULTQUEUE,WRITE)) < 0)
                ErrorExit(QUEUE_FATAL,ARGV0, DEFAULTQUEUE);
        }
    }

    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR,ARGV0);

    /* Reading the private keys for secure connection */
    if(connection_type == SECURE_CONN)
        ReadKeys(&keys);

    while(1)
    {
        if(_local_err == 5)
            ErrorExit(QUEUE_FATAL,ARGV0,DEFAULTQUEUE);

        buffer = OS_RecvAllUDP(sock, OS_MAXSTR, srcip, IPSIZE);

        if(buffer == NULL)
            continue;

        if((connection_type == SECURE_CONN) && 
                (CheckAllowedIP(&keys,srcip,NULL) == -1)) 
        {
            merror(DENYIP_ERROR,ARGV0,srcip);
            free(buffer);
            continue;
        }

        /* Only checking it if connection is != SECURE (syslog) */
        else if((connection_type != SECURE_CONN)&&
                (OS_IPNotAllowed(srcip,logr)))
        {
            merror(DENYIP_ERROR,ARGV0,srcip);
            free(buffer);
            continue;
        }

        if(connection_type == SECURE_CONN)
        {
            char *cleartext_msg = NULL;
            
            cleartext_msg = ReadSecMSG(&keys, srcip, buffer);
            
            if(cleartext_msg == NULL)
            {
                merror(MSG_ERROR,ARGV0,srcip);
                free(buffer);
                continue;
            }

            /* If we can't send the message, try to connect to the
             * socket again. If not, increments local_err, rest a 
             * little bit and try again latter
             */
            if(SendMSG(m_queue, cleartext_msg, srcip,logr->group[position],
                        SECURE_MQ) < 0)
            {
                merror(QUEUE_ERROR,ARGV0,DEFAULTQUEUE);
                
                if((m_queue = StartMQ(DEFAULTQUEUE,READ)) < 0)
                {
                    merror(QUEUE_ERROR,ARGV0,DEFAULTQUEUE);
                    sleep(_local_err);
                }
                
                _local_err++;
            }
            else
                _local_err = 0;

            free(cleartext_msg);    
        }

        else
        {	
            if(SendMSG(m_queue,buffer,srcip,logr->group[position],
                        SYSLOG_MQ) < 0)
            {
                merror(QUEUE_ERROR,ARGV0,DEFAULTQUEUE);
                if((m_queue = StartMQ(DEFAULTQUEUE,READ)) < 0)
                {
                    merror(QUEUE_ERROR,ARGV0,DEFAULTQUEUE);
                    sleep(_local_err);
                }
                _local_err++;
            }
            else
                _local_err=0;
        }
        
        free(buffer);
    }
}


/* main, v0.2, 2004/08/05
 */
int main(int argc, char **argv)
{
    
    int c,binds=0,i=0,uid=0,gid=0;
    
    remoted logr;
    
    int connection_type=0;
    
    char *cfg=DEFAULTCPATH;
    char *dir=DEFAULTDIR;
    char *user=REMUSER;
    char *group=GROUPGLOBAL;

    while((c = getopt(argc, argv, "dhu:g:D:")) != -1){
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
                user = optarg;
                break;
            case 'g':
                if(!optarg)
                    ErrorExit("%s: -g needs an argument",ARGV0);
                group = optarg;
                break;		
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                dir = optarg;
        }
    }

    debug1(STARTED_MSG,ARGV0);
    
    /* Return 0 if not configured */
    if((binds = BindConf(cfg,&logr)) == 0)
    {	
        merror(CONN_ERROR,ARGV0);
        exit(0);
    }

    /* Return < 0 if bad configured */
    else if(binds < 0)
        ErrorExit(CONFIG_ERROR,ARGV0);

    /*Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
        ErrorExit(USER_ERROR,user,group);


    /* Starting the signal manipulation */
    StartSIG(ARGV0);	


    /* Really starting the program. */
    for(i=0;i<binds;i++)
    {
        if(!logr.conn[i])
        {
            merror(CONNTYPE_ERROR,ARGV0,logr.conn[i]);
            continue;
        }
        
        else if(strcmp(logr.conn[i],"syslog") == 0)
            connection_type=SYSLOG_CONN;
            
        else if (strcmp(logr.conn[i],"secure") == 0)
            connection_type=SECURE_CONN;
            
        else
        {
            merror(CONNTYPE_ERROR,ARGV0,logr.conn[i]);
            continue;
        }
        
        if(fork() == 0)
            _startit(i,connection_type,uid,gid,dir,&logr);
        else
            continue;
    }
    return(0);
}

/* EOF */
