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

#include "remoted.h"



/** void HandleRemote(int position, int uid) v0.2 2005/11/09
 * Handle remote connections
 * v0.2, 2005/11/09
 * v0.1, 2004/7/30
 */
void HandleRemote(int position, int uid)
{
    /* If syslog connection and allowips is not defined, exit */
    if((logr.allowips == NULL)&&(logr.conn[position] == SYSLOG_CONN))
    {
        ErrorExit(NO_SYSLOG, ARGV0);
    }
    
    
    /* Checking if the port is valid */       
    if((logr.port[position] < 0) || (logr.port[position] > 65535))
    {
        merror(PORT_ERROR, ARGV0, logr.port[position]);
        logr.port[position] = 0;
    }
   
    /* Setting up default ports */ 
    if(logr.port[position] == 0)
    {
        if(logr.conn[position] == SYSLOG_CONN)
            logr.port[position] = DEFAULT_SYSLOG;
        else
            logr.port[position] = DEFAULT_SECURE;
    }

    
    /* Only using UDP. Fast, unreliable.. perfect */
    if((logr.sock = OS_Bindportudp(logr.port[position],NULL)) < 0)
        ErrorExit(BIND_ERROR, ARGV0, logr.port[position]);

   
   
    /* Revoking the privileges */
    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR,ARGV0, uid);
                    
    
     
    /* Connecting to the message queue
     * Exit if it fails.
     */
    if((logr.m_queue = StartMQ(DEFAULTQUEUE,WRITE)) < 0)
    {	
        ErrorExit(QUEUE_FATAL,ARGV0, DEFAULTQUEUE);
    }


    /* Creating PID */
    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR,ARGV0);


    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, getpid());
        

    /* If Secure connection, deal with it */
    if(logr.conn[position] == SECURE_CONN)
    {
        HandleSecure(position);
    }

    /* If not, deal with syslog */
    else
    {
        HandleSyslog(position);
    }
    
    return;
}


/* EOF */
