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


#include "shared.h"
#include "agentd.h"

#include "os_net/os_net.h"



/* AgentdStart v0.2, 2005/11/09
 * Starts the agent daemon.
 */
void AgentdStart(char *dir, int uid, int gid)
{
    int rc = 0;
    int pid = 0;
    int maxfd = 0;   
    int total = 0;

    fd_set fdset;
    
    struct timeval fdtimeout;

    
    /* Going daemon */
    pid = getpid();
    nowDaemon();
    goDaemon();

    
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

    maxfd = logr->m_queue;
    


    /* Creating PID file */	
    if(CreatePID(ARGV0, getpid()) < 0)
        merror(PID_ERROR,ARGV0);


    /* Reading the private keys  */
    ReadKeys(&keys, 0);


    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, getpid());

    
    /* Initial random numbers */
    srand( time(0) + getpid() + pid + getppid() );
    rand();


    /* Connecting UDP */
    logr->sock = OS_ConnectUDP(logr->port,logr->rip);
    if(logr->sock < 0)
        ErrorExit(CONNS_ERROR,ARGV0,logr->rip);

    
    /* Setting max fd for select */
    if(logr->sock > maxfd)
    {
        maxfd = logr->sock;
    }

    /* Connecting to the execd queue */
    if(logr->execdq == 0)
    {
        if((logr->execdq = StartMQ(EXECQUEUE, WRITE)) < 0)
        {
            merror(ARQ_ERROR, ARGV0);
        }
    }


    /* Creating mutexes */
    pthread_mutex_init(&receiver_mutex, NULL);
    pthread_mutex_init(&forwarder_mutex, NULL);
    pthread_mutex_init(&notify_mutex, NULL);
    pthread_cond_init (&receiver_cond, NULL);
    pthread_cond_init (&forwarder_cond, NULL);
    pthread_cond_init (&notify_cond, NULL);

    
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
    if(CreateThread(EventForward, (void *)NULL) != 0)
    {
        ErrorExit(THREAD_ERROR, ARGV0);
    }
    
    
    /* Maxfd must be higher socket +1 */
    maxfd++;
    
    
    /* monitor loop */
    while(1)
    {
        /* Monitoring all available sockets from here */
        FD_ZERO(&fdset);
        FD_SET(logr->sock, &fdset);
        FD_SET(logr->m_queue, &fdset);

        fdtimeout.tv_sec = 120;
        fdtimeout.tv_usec = 0;

        
        /* Only notify when total is 0 */ 
        if(!total)
        { 
            /* Sending signal to notifier */
            if(pthread_mutex_lock(&notify_mutex) != 0)
            {
                merror(MUTEX_ERROR, ARGV0);
                return;
            }

            pthread_cond_signal(&notify_cond);    
            if(pthread_mutex_unlock(&notify_mutex) != 0)
            {
                merror(MUTEX_ERROR, ARGV0);
                return;
            }

            total++;
        }
        
        
        /* Wait for 120 seconds at a maximum for any descriptor */
        rc = select(maxfd, &fdset, NULL, NULL, &fdtimeout);
        if(rc == -1)
        {
            ErrorExit(SELECT_ERROR, ARGV0);
        }
       
        
        /* If timeout, do not signal to other threads */
        else if(rc == 0)
        {
            total = 0;
            continue;
        }    
        
        /* Zero on every 120 events */
        else if(total >=120)
        {
            total = 0;
        }

        else
        {
            total++;
        }
        
        
        /* For the receiver */
        if(FD_ISSET(logr->sock, &fdset))
        {
            if(pthread_mutex_lock(&receiver_mutex) != 0)
            {
                merror(MUTEX_ERROR, ARGV0);
                return;
            }

            available_receiver = 1;
            pthread_cond_signal(&receiver_cond);
            
            if(pthread_mutex_unlock(&receiver_mutex) != 0)
            {
                merror(MUTEX_ERROR, ARGV0);
                return;
            }

        }

        
        /* For the forwarder */
        if(FD_ISSET(logr->m_queue, &fdset))
        {
             if(pthread_mutex_lock(&forwarder_mutex) != 0)
            {
                merror(MUTEX_ERROR, ARGV0);
                return;
            }

            available_forwarder = 1; 
            pthread_cond_signal(&forwarder_cond);
            
            if(pthread_mutex_unlock(&forwarder_mutex) != 0)
            {
                merror(MUTEX_ERROR, ARGV0);
                return;
            }
        }

        /* Sleep in here. Each thread is already reading what they
         * have available.
         */
        sleep(1); 
        
        
    }
}



/* EOF */
