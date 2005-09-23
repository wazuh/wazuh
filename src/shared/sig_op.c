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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "headers/sig_op.h"
#include "headers/file_op.h"

char *pidfile = NULL;

void HandleSIG()
{
    (void)fprintf(stderr, "%s: SIGNAL Received. Exit Cleaning...\n",
                  pidfile);
    
    DeletePID(pidfile);
    
    exit(1);
}

/* To avoid client-server communication problems */
void HandleSIGPIPE()
{
    /*(void)fprintf(stderr, "SIGPIPE Received. Ignoring ..\n");*/
    /* Should not use printf if we are going to back to the previous
     * point in the code
     */
    #ifdef DEBUG
    (void)fprintf(stderr, "%s: SIGPIPE Received. Ignoring...\n",
                    pidfile); 
    #endif
    
    return;
}

void StartSIG(char *process_name)
{
    /* Signal Manipulation
       go to HandleSIG() */
    pidfile = process_name;
    
    signal(SIGINT, HandleSIG);
    signal(SIGQUIT, HandleSIG);
    signal(SIGTERM, HandleSIG);
    signal(SIGALRM, HandleSIG);
    signal(SIGPIPE, HandleSIGPIPE);
}

/* EOF */
