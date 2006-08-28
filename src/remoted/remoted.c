/* @(#) $Id$ */

/* Copyright (C) 2003,2004,2005,2006 Daniel B. Cid <dcid@ossec.net>
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


#include "shared.h"
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
    
    /* Bind TCP */ 
    if(logr.proto[position] == TCP_PROTO)
    {
        if((logr.sock = 
            OS_Bindporttcp(logr.port[position],logr.lip[position])) < 0)
        {
            ErrorExit(BIND_ERROR, ARGV0, logr.port[position]);
        }
    }
    else
    {
        /* Using UDP. Fast, unreliable.. perfect */
        if((logr.sock = 
            OS_Bindportudp(logr.port[position], logr.lip[position])) < 0)
        {
            ErrorExit(BIND_ERROR, ARGV0, logr.port[position]);
        }
    }

   
   
    /* Revoking the privileges */
    if(Privsep_SetUser(uid) < 0)
    {
        ErrorExit(SETUID_ERROR,ARGV0, uid);
    }
                    
    
    /* Creating PID */
    if(CreatePID(ARGV0, getpid()) < 0)
    {
        ErrorExit(PID_ERROR,ARGV0);
    }


    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, getpid());
        

    /* If Secure connection, deal with it */
    if(logr.conn[position] == SECURE_CONN)
    {
        HandleSecure();
    }
    
    else if(logr.proto[position] == TCP_PROTO)
    {
        HandleSyslogTCP();
    }
    
    /* If not, deal with syslog */
    else
    {
        HandleSyslog();
    }
    
    return;
}


/* EOF */
