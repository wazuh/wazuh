/*   $OSSEC, agentd.c, v0.2, 2005/06/30, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC HIDS
 * Available at http://www.ossec.net/hids/
 */


/* agent daemon.
 */


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef LOGCLIENT
   #define LOGCLIENT
#endif

#ifndef ARGV0
   #define ARGV0 "ossec-agentd"
#endif

#include "agentd.h"

#include "os_net/os_net.h"

#include "headers/defs.h"
#include "headers/mq_op.h"
#include "headers/debug_op.h"
#include "headers/sig_op.h"
#include "headers/help.h"
#include "headers/privsep_op.h"
#include "headers/file_op.h"
#include "headers/sec.h"

#include "error_messages/error_messages.h"


/* External debug and chroot flags */
short int dbg_flag=0;
short int chroot_flag=0;


/* _startit v0.1, 2005/01/30
 * Internal Function. Does all the socket/ queueing
 * manipulation.
 * Maximum allowed input is 1024 bytes.
 */
void _startit(agent *logr, char *dir, int uid, int gid)
{
    int m_queue = 0;    
    unsigned short int rand0; /* Rand addition */
    unsigned int port = 0;
    int sock;
    keystruct keys;

    if((logr->port == NULL) || (port = atoi(logr->port) <= 0))
    {
        port = DEFAULT_SECURE;
        /* merror(PORT_ERROR,ARGV0,port); */
    }

    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,gid);

    if(Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR,ARGV0,dir);

    chroot_flag = 1; /* Inside chroot now */

    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR,ARGV0,uid);

    /* Create the queue. In this case we are going to create
     * and read from it
     * Exit if fails.
     */
    if((m_queue = StartMQ(DEFAULTQUEUE,READ)) < 0)
        ErrorExit(QUEUE_ERROR,ARGV0,DEFAULTQUEUE);

    /* Creating PID file */	
    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR,ARGV0);

    /* Reading the private keys  */
    ReadKeys(&keys);

    /* Connecting UDP */
    sock = OS_ConnectUDP(port,logr->rip);
    if(sock < 0)
        ErrorExit(CONNS_ERROR,ARGV0,logr->rip);

    /* Initial random numbers */
    srand( time(0)+getpid()+getppid() );
    rand0 = (unsigned short int)rand();

    /* daemon loop */	
    for(;;)
    {
        char *msg = NULL;

        /* Receiving from the unix queue */
        if((msg = OS_RecvUnix(m_queue, OS_MAXSTR)) != NULL)
        {
            char *crypt_msg = NULL;
            int _ssize = 0; /* msg socket size */

            rand0 = (unsigned short int)rand(); /* new random */
            crypt_msg = CreateSecMSG(&keys, msg, 0, &_ssize, rand0);
            
            /* Returns NULL if can't create encrypted message */
            if(crypt_msg == NULL)
            {
                merror(SEC_ERROR,ARGV0);
                free(msg);
                continue;
            }

            /* Send _ssize of crypt_msg */
            if(OS_SendUDPbySize(sock, _ssize, crypt_msg) < 0)
                merror(SEND_ERROR,ARGV0);

            /* No need to set them to null */
            free(crypt_msg);
            free(msg);
        }
    }
}

/* main, v0.1, 2005/01/30
 */
int main(int argc, char **argv)
{
    int c = 0;
    int binds = 0;
    
    char *dir=DEFAULTDIR;
    char *user=USER;
    char *group=GROUPGLOBAL;
    
    int uid=0;
    int gid=0;

    agent logr;

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
                break;
        }
    }

    debug1("%s: Starting ... ",ARGV0);

    if((binds = ClientConf(DEFAULTCPATH,&logr)) == 0)
        ErrorExit(CLIENT_ERROR,ARGV0);

    else if(binds < 0)
        ErrorExit(CONFIG_ERROR,ARGV0);

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
        ErrorExit(USER_ERROR,ARGV0,user,group);

    /* Starting the signal manipulation */
    StartSIG(ARGV0);	

    if(fork() == 0)
    {
        /* Forking and going to background */
        _startit(&logr,dir,uid,gid);
    }
    return(0);
}

