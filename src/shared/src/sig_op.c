/* Copyright (C) Wazuh Inc.
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
#include <stdatomic.h>
#include <string.h>

#include "shared.h"
#include "sig_op.h"
#include "file_op.h"
#include "debug_op.h"
#include "error_messages.h"
#include "debug_messages.h"

static const char *pidfile = NULL;

// Lock-free, so the store below is async-signal-safe and the loads in other threads need no lock.
// Relaxed is enough: the flag only ever goes false -> true and carries no other data.
static _Atomic int shutdown_requested = 0;

bool w_shutdown_requested(void) {
    return atomic_load_explicit(&shutdown_requested, memory_order_relaxed) != 0;
}

void w_shutdown_requested_set(bool value) {
    atomic_store_explicit(&shutdown_requested, value ? 1 : 0, memory_order_relaxed);
}

void HandleExit() {
    DeletePID(pidfile);

    if (strcmp(__local_name, "unset")) {
        DeleteState();
    }
}

void HandleSIG(int sig)
{
    // Before anything else: exit() below runs the atexit handlers while the other threads are still
    // live, and the wazuh-db client reads this flag to tell a peer stopped alongside from a lost one.
    w_shutdown_requested_set(true);

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
