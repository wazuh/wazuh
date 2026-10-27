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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "shared.h"
#include "sig_op.h"
#include "file_op.h"
#include "debug_op.h"
#include "error_messages/error_messages.h"
#include "error_messages/debug_messages.h"

#ifdef WAZUH_UNIT_TESTING
#define STATIC
#else
#define STATIC static
#endif

static const char *pidfile = NULL;

/* The shutdown thread reads sig_pipe_rd; the handler writes sig_pipe_wr, which is only set once the thread runs */
STATIC int sig_pipe_rd = -1;
STATIC volatile int sig_pipe_wr = -1;
STATIC volatile sig_atomic_t sig_received = 0;
STATIC void (*volatile sig_shutdown_func)(void) = NULL;

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

/* Legacy exit() path unless StartSIGShutdownThread() ran; then it only wakes the thread, since exit() here
 * would run atexit handlers under threads still using their resources.
 * A second termination signal is ignored so the shutdown work can finish; a stuck shutdown is escalated to
 * SIGKILL by the service manager or wazuh-control. */
void HandleSIG(int sig)
{
    int saved_errno = errno;

    if (sig_pipe_wr < 0) {
        minfo(SIGNAL_RECV, sig, strsignal(sig));
        exit(1);
    }

    if (sig_received == 0) {
        sig_received = sig;

        while (write(sig_pipe_wr, "", 1) < 0 && errno == EINTR) {}
    }

    errno = saved_errno;
}

/* Runs the shutdown work outside signal context, then ends the process without running the atexit handlers */
STATIC void SIGShutdown(void)
{
    int sig = (int)sig_received;
    void (*func)(void) = sig_shutdown_func;

    minfo(SIGNAL_RECV, sig, strsignal(sig));

    if (func) {
        func();
    }

    HandleExit();
    _exit(1);
}

STATIC void *SIGShutdownThread(__attribute__((unused)) void *arg)
{
    char buf;
    ssize_t len;

    while (len = read(sig_pipe_rd, &buf, 1), len < 0 && errno == EINTR) {}

    if (len != 1) {
        /* The pipe is unusable, so no signal can wake this thread: fall back to the legacy exit() path */
        sig_pipe_wr = -1;
        merror("The shutdown pipe is unusable. Termination signals will exit directly.");
        return NULL;
    }

    SIGShutdown();

    return NULL;
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

void StartSIGShutdownThread()
{
    int fds[2];

    if (pipe(fds) < 0) {
        merror("Could not create the shutdown pipe: %s (%d). Termination signals will exit directly.", strerror(errno), errno);
        return;
    }

    fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    fcntl(fds[1], F_SETFL, fcntl(fds[1], F_GETFL, 0) | O_NONBLOCK);

    sig_pipe_rd = fds[0];
    w_create_thread(SIGShutdownThread, NULL);

    /* Arm the handler only once the thread is there to wake */
    sig_pipe_wr = fds[1];
}

void SetSIGShutdownFunc(void (*func)(void))
{
    sig_shutdown_func = func;
}

#endif /* !WIN32 */
