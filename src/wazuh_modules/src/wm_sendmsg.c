/*
 * Wazuh Module Manager: sending module events to a local queue
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

#include "wmodules.h"

#ifndef WIN32
// The delay as select() takes it. tv_usec stays below a second, which macOS requires: max_eps=1 gives
// a delay of 1000000 microseconds.
STATIC struct timeval wm_sendmsg_timeval(int usec) {
    struct timeval timeout = {usec / 1000000, usec % 1000000};
    return timeout;
}
#endif

// Wait the given delay, which keeps a module under its events per second
static void wm_sendmsg_delay(int usec) {

#ifdef WIN32
    int msec = usec / 1000;
    Sleep(msec);
#else
    struct timeval timeout = wm_sendmsg_timeval(usec);
    select(0, NULL, NULL, NULL, &timeout);
#endif
}

// Send message to a queue waiting for a specific delay
int wm_sendmsg(int usec, int queue, const char *message, const char *locmsg, char loc) {

    wm_sendmsg_delay(usec);

    if (SendMSG(queue, message, locmsg, loc) < 0) {
        mdebug1("Unable to send message to queue: (%s)", strerror(errno));
        return -1;
    }

    return 0;
}

// Send message to a queue waiting for a specific delay
int wm_sendmsg_ex(int usec, int queue, const char *message, const char *locmsg, char loc, bool (*fn_prd)()) {

    wm_sendmsg_delay(usec);

    if (SendMSGPredicated(queue, message, locmsg, loc, fn_prd) < 0) {
        mdebug1("Unable to send message to queue: (%s)", strerror(errno));
        return -1;
    }

    return 0;
}

// Predicate for the waits below: stop waiting once modulesd is shutting down.
static bool wm_sendmsg_shutdown_requested(void) {
    return wm_shutdown_requested != 0;
}

// Predicate for the sends: SendMSGPredicated() waits for the agent again, but the helper has just done
// that wait and decided to send, so the second one must not hold the message.
static bool wm_sendmsg_already_waited(void) {
    return true;
}

// Wait while wazuh-agentd holds its producers back because it can't reach the manager, unless modulesd
// is already shutting down. False when modulesd is shutting down and the agent still can't reach the
// manager: a stopping agent may never forward the message, so the caller keeps it. An agent that can
// still forward it gets it, as on a reload, which keeps wazuh-agentd running.
static bool wm_sendmsg_agent_ready(const char *tag) {
    if (!wm_sendmsg_shutdown_requested()) {
        os_wait_predicate(wm_sendmsg_shutdown_requested);
    }

    if (wm_sendmsg_shutdown_requested() && os_iswait()) {
        mtdebug1(tag, "Message not sent: modulesd is stopping and the agent can't reach the manager.");
        return false;
    }

    return true;
}

#ifndef WIN32
// Reopen DEFAULTQUEUE into *queue, retrying every 5 seconds until wazuh-agentd binds it again or
// modulesd is shutting down.
static int wm_sendmsg_reopen(int *queue, const char *tag) {
    *queue = MQReconnectPredicated(DEFAULTQUEUE, wm_sendmsg_shutdown_requested);

    if (*queue >= 0) {
        mtinfo(tag, SUCCESSFULLY_RECONNECTED_SOCKET, DEFAULTQUEUE);
    }

    return *queue;
}

// The send failed: SendMSGAction() closed the descriptor, or an earlier call had already dropped it.
// Reopen the queue and send once more.
static int wm_sendmsg_resend(int *queue, const char *message, const char *locmsg, char loc, const char *tag) {

    if (wm_sendmsg_reopen(queue, tag) < 0 || !wm_sendmsg_agent_ready(tag)) {
        return -1;
    }

    if (wm_sendmsg_ex(0, *queue, message, locmsg, loc, wm_sendmsg_already_waited) < 0) {
        // Closed again: the number may already belong to another thread.
        *queue = -1;
        return -1;
    }

    return 0;
}
#endif

// Send message to a queue waiting for a specific delay, reopening the queue if the send fails
int wm_sendmsg_with_reconnect(int usec, int *queue, const char *message, const char *locmsg, char loc, const char *tag) {

    wm_sendmsg_delay(usec);

    if (!wm_sendmsg_agent_ready(tag)) {
        return -1;
    }

    if (wm_sendmsg_ex(0, *queue, message, locmsg, loc, wm_sendmsg_already_waited) == 0) {
        return 0;
    }

#ifdef WIN32
    // Windows modules hand their events to the agent in process: there is no socket to reopen.
    return -1;
#else
    return wm_sendmsg_resend(queue, message, locmsg, loc, tag);
#endif
}
