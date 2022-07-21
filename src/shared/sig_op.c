/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions to handle signal manipulation */

#ifndef WIN32

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include "shared.h"
#include "sig_op.h"
#include "file_op.h"
#include "debug_op.h"
#include "error_messages/error_messages.h"
#include "error_messages/debug_messages.h"

static const char *pidfile = NULL;

/* To avoid hp-ux requirement of strsignal */
#ifdef __hpux
char* strsignal(int sig)
{
    static char str[12];
    sprintf(str, "%d", sig);
    return str;
}
#endif

void HandleExit() {
    DeletePID(pidfile);

    if (strcmp(__local_name, "unset")) {
        DeleteState();
    }
}

void HandleSIG(int sig)
{
    minfo(SIGNAL_RECV, sig, strsignal(sig));

    exit(1);
}


/* To avoid client-server communication problems */
void HandleSIGPIPE(__attribute__((unused)) int sig)
{
    return;
}

void StartSIG(const char *process_name)
{
    pidfile = process_name;

    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, HandleSIG);
    signal(SIGQUIT, HandleSIG);
    signal(SIGTERM, HandleSIG);
    signal(SIGALRM, HandleSIG);
    signal(SIGPIPE, HandleSIGPIPE);

    atexit(HandleExit);
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

    atexit(HandleExit);
}

#endif /* !WIN32 */
