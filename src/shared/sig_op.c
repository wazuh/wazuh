/*      $OSSEC, sig_op.c, v0.2, 2004/08/03, Daniel B. Cid$      */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Functions to handle signal manipulation
 */

#ifndef WIN32

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "sig_op.h"
#include "file_op.h"
#include "debug_op.h"

#include "error_messages/error_messages.h"

char *pidfile = NULL;

void HandleSIG()
{
    merror(SIGNAL_RECV, pidfile);
    
    DeletePID(pidfile);
    
    exit(1);
}


/* To avoid client-server communication problems */
void HandleSIGPIPE()
{
    return;
}

void StartSIG(char *process_name)
{
    /* Signal Manipulation
       go to HandleSIG() */
    pidfile = process_name;

    signal(SIGHUP, SIG_IGN);    
    signal(SIGINT, HandleSIG);
    signal(SIGQUIT, HandleSIG);
    signal(SIGTERM, HandleSIG);
    signal(SIGALRM, HandleSIG);
    signal(SIGPIPE, HandleSIGPIPE);
}

#endif
/* EOF */
