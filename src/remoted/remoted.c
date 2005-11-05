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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>  
#include <arpa/inet.h>
#include <time.h>

#include "os_net/os_net.h"

#ifndef ARGV0
   #define ARGV0 "ossec-remoted"
#endif

#include "remoted.h"

#include "shared.h"

#include "sec.h"



/*  manager prototypes */
void manager_init();
void start_mgr(int agentid, char *msg, char *srcip);
char *r_read(char *tmp_msg);



/* OS_IPNotAllowed, v0.1, 2005/02/11 
 * Checks if an IP is not allowed.
 */
int OS_IPNotAllowed(char *srcip)
{
    if(logr.denyips != NULL)
    {
        int i=0;
        for(i=0;i<255;i++) /* Maximum access-list */
        {
            if(logr.denyips[i] == NULL)
                break;
            if(strncmp(logr.denyips[i],srcip,strlen(logr.denyips[i]))==0)
                return(1);
        }
    }
    if(logr.allowips != NULL)
    {
        int i=0;
        for(i=0;i<255;i++) /* Maximum access-list */
        {
            if(logr.allowips[i] == NULL)
                break;
            if(strncmp(logr.allowips[i],srcip,
                        strlen(logr.allowips[i]))==0)
                return(0);
        }
    }

    /* If the ip is not allowed, it will be denied */
    return(1);
}


/* _startit v0.1, 2004/7/30
 * Internal Function. Does all the socket/ queueing
 * manipulation.
 * Maximum allowed input is MAXSTR.
 */
void _startit(int position, int connection_type, int uid, 
              int gid, char *dir)
{
    int sock;
    int m_queue;
    int agentid;
    
    char buffer[OS_MAXSTR +1];
    char cleartext_msg[OS_MAXSTR +1]; 
    char srcip[IPSIZE +1];
    char *tmp_msg;
    
    int port = 0;
   
    int recv_b;
    
    struct sockaddr_in peer_info;
    socklen_t peer_size;
    
    
    /* if SYSLOG and allowips is not defined, exit */
    if((logr.allowips == NULL)&&(connection_type == SYSLOG_CONN))
    {
        ErrorExit(NO_SYSLOG, ARGV0);
    }
    
    /* Checking if the port is valid */       
    if((logr.port == NULL ) ||
       (logr.port[position] == NULL )||
       ((port = atoi(logr.port[position])) <= 0) ||
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


    nowChroot();


    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR,ARGV0, uid);

    
    /* Initializing manager and forwarder if 
     * secure connection.
     */
    if(connection_type == SECURE_CONN)
    {
        /* Initing manager */
        manager_init();


        /* Starting Ar forwarder */
        if(CreateThread(AR_Forward, (void *)NULL) != 0)
        {
            ErrorExit(THREAD_ERROR, ARGV0);
        }
    }
    
    
    /* Connecting to the message queue
     * Exit if it fails.
     */
    if((m_queue = StartMQ(DEFAULTQUEUE,WRITE)) < 0)
    {	
        ErrorExit(QUEUE_FATAL,ARGV0, DEFAULTQUEUE);
    }


    /* Creating PID */
    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR,ARGV0);


    /* Reading the private keys for secure connection */
    if(connection_type == SECURE_CONN)
    {
        /* Read the keys */ 
        ReadKeys(&keys);
    }


    /* setting peer size */
    peer_size = sizeof(peer_info);
    logr.peer_size = sizeof(peer_info);


    /* Initializing some variables */
    memset(buffer, '\0', OS_MAXSTR +1);
    memset(cleartext_msg, '\0', OS_MAXSTR +1);
    tmp_msg = NULL;

    
    /* Infinit loop in here */
    while(1)
    {
        /* Receiving message  */
        recv_b = recvfrom(sock, buffer, OS_MAXSTR, 0, 
                          (struct sockaddr *)&peer_info, &peer_size);

        /* Nothing received */
        if(recv_b <= 0)
            continue;
        
        
        /* Setting the source ip */
        strncpy(srcip, inet_ntoa(peer_info.sin_addr), IPSIZE);
        srcip[IPSIZE] = '\0';
            
        
        /* Handling secure connections */
        if(connection_type == SECURE_CONN)
        {
  
            /* Getting a valid agentid */ 
            agentid = IsAllowedIP(&keys, srcip); 
            if(agentid < 0)
            {
                merror(DENYIP_ERROR,ARGV0,srcip);
                continue;
            }
        
            /* Decrypting the message */    
            tmp_msg = ReadSecMSG(&keys, buffer, cleartext_msg,
                                        agentid,recv_b -1);
            if(tmp_msg == NULL)
            {
                merror(MSG_ERROR,ARGV0,srcip);
                continue;
            }

             
            /* Check if it is a control message */ 
            if((tmp_msg[0] == '#') && (tmp_msg[1] == '!') &&
                                      (tmp_msg[2] == '-'))
            {
                tmp_msg+=3;

                /* We need to save the peerinfo if it is a control msg */
                memcpy(&keys.peer_info[agentid], &peer_info, peer_size);
                                                
                merror("contro message, starting manager: %s\n", inet_ntoa(keys.peer_info[agentid].sin_addr));
                start_mgr(agentid, tmp_msg, srcip); 
            }
            
            
            /* If we can't send the message, try to connect to the
             * socket again. If not, increments local_err and try
             * again latter
             */
            else if(SendMSG(m_queue, tmp_msg, srcip, logr.group[position],
                        SECURE_MQ) < 0)
            {
                merror(QUEUE_ERROR,ARGV0,DEFAULTQUEUE);
                
                if((m_queue = StartMQ(DEFAULTQUEUE,READ)) < 0)
                {
                    ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
                }
            }
        }

        /* syslog message */
        else
        {
            /* Checking if IP is allowed here */
            if(OS_IPNotAllowed(srcip))
            {
                merror(DENYIP_ERROR,ARGV0,srcip);
            }
            
            else if(SendMSG(m_queue,buffer,srcip,logr.group[position],
                        SYSLOG_MQ) < 0)
            {
                merror(QUEUE_ERROR,ARGV0,DEFAULTQUEUE);
                if((m_queue = StartMQ(DEFAULTQUEUE,READ)) < 0)
                {
                    ErrorExit(QUEUE_FATAL,ARGV0,DEFAULTQUEUE);
                }
            }
        }
    }
}


/* main, v0.2, 2004/08/05
 */
int main(int argc, char **argv)
{
    int c,binds = 0,i = 0,uid = 0,gid = 0;
    
    
    int connection_type = 0;
    
    char *cfg = DEFAULTCPATH;
    char *dir = DEFAULTDIR;
    char *user = REMUSER;
    char *group = GROUPGLOBAL;

    while((c = getopt(argc, argv, "dhu:g:D:")) != -1){
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
        #ifndef LOCAL_ONLY
        merror(CONN_ERROR,ARGV0);
        #endif
        
        exit(0);
    }


    /* Return < 0 on error */
    else if(binds < 0)
        ErrorExit(CONFIG_ERROR,ARGV0);


    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
        ErrorExit(USER_ERROR,user,group);


    /* Starting the signal manipulation */
    StartSIG(ARGV0);	


    i = getpid();


    /* Going on daemon */
    nowDaemon();
    goDaemon();

    
    /* Creating some randoness  */
    srand( time(0) + getpid()+ i);
    rand();
                

    /* Really starting the program. */
    for(i=0;i < binds; i++)
    {
        if(!logr.conn[i])
        {
            merror(CONNTYPE_ERROR,ARGV0,logr.conn[i]);
            continue;
        }
        
        else if(strcmp(logr.conn[i],"syslog") == 0)
            connection_type = SYSLOG_CONN;
            
        else if (strcmp(logr.conn[i],"secure") == 0)
            connection_type = SECURE_CONN;
            
        else
        {
            merror(CONNTYPE_ERROR,ARGV0,logr.conn[i]);
            continue;
        }
        
        /* Forking for each connection handler */
        if(fork() == 0)
        {   
            /* On the child */
            _startit(i, connection_type, uid, gid, dir);
        }
        else
        {
            continue;
        }
    }


    /* Done over here */
    return(0);
}

/* EOF */
