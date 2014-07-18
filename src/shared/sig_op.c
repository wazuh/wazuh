/* @(#) $Id: ./src/shared/sig_op.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
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

static const char *pidfile = NULL;

void HandleSIG(__attribute__((unused)) int sig)
{
    merror(SIGNAL_RECV, pidfile);

    DeletePID(pidfile);

    exit(1);
}


/* To avoid client-server communication problems */
void HandleSIGPIPE(__attribute__((unused)) int sig)
{
    return;
}

void StartSIG(const char *process_name)
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

void StartSIG2(const char *process_name, void (*func)(int))
{
    pidfile = process_name;

    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, func);
    signal(SIGQUIT, func);
    signal(SIGTERM, func);
    signal(SIGALRM, func);
    signal(SIGPIPE, HandleSIGPIPE);
}

#endif
/* EOF */
