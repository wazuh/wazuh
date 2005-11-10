/*   $OSSEC, agentd.c, v0.3, 2005/11/09, Daniel B. Cid$   */

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



#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "agentd.h"

#include "os_net/os_net.h"



/* AgentdStart v0.2, 2005/11/09
 * Starts the agent daemon.
 */
void AgentdStart(char *dir, int uid, int gid)
{
    int pid;
    int port = 0;
    

    /* Giving the default port if none is available */
    if((logr->port == NULL) || (port = atoi(logr->port) <= 0))
    {
        port = DEFAULT_SECURE;
    }

    /* Setting group ID */
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR, ARGV0, gid);

    /* chrooting */
    if(Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR, ARGV0, dir);

    
    nowChroot();


    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR, ARGV0, uid);


    /* Create the queue. In this case we are going to create
     * and read from it
     * Exit if fails.
     */
    if((logr->m_queue = StartMQ(DEFAULTQUEUE,READ)) < 0)
        ErrorExit(QUEUE_ERROR,ARGV0,DEFAULTQUEUE);



    /* Going daemon */
    pid = getpid();
    nowDaemon();
    goDaemon();


    /* Creating PID file */	
    if(CreatePID(ARGV0, getpid()) < 0)
        merror(PID_ERROR,ARGV0);


    /* Reading the private keys  */
    ReadKeys(&keys);

    
    /* Initial random numbers */
    srand( time(0) + getpid() + pid + getppid() );
    rand();


    /* Connecting UDP */
    logr->sock = OS_ConnectUDP(port,logr->rip);
    if(logr->sock < 0)
        ErrorExit(CONNS_ERROR,ARGV0,logr->rip);


    /* Connecting to the execd queue */
    if((logr->execdq = StartMQ(EXECQUEUE, WRITE)) < 0)
    {
        ErrorExit(ARQ_ERROR, ARGV0);
    }


    /* Starting receiver thread.
     * Receive events/commands from the server
     */
    if(CreateThread(receiver_thread, (void *)NULL) != 0)
    {
        ErrorExit(THREAD_ERROR, ARGV0);
    }

    
    /* Starting notification thread.
     * Sends file information to the server
     */
    if(CreateThread(notify_thread, (void *)NULL) != 0)
    {
        ErrorExit(THREAD_ERROR, ARGV0);
    }

    
    /* Starting the Event Forwarder */
    EventForward();
    
}



/* EOF */
