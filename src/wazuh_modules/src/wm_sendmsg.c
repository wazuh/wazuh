/*
 * Wazuh Module Manager: sending module events to a local queue
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"

// Send message to a queue waiting for a specific delay
int wm_sendmsg(int usec, int queue, const char *message, const char *locmsg, char loc) {

#ifdef WIN32
    int msec = usec / 1000;
    Sleep(msec);
#else
    struct timeval timeout = {0, usec};
    select(0, NULL, NULL, NULL, &timeout);
#endif

    if (SendMSG(queue, message, locmsg, loc) < 0) {
        mdebug1("Unable to send message to queue: (%s)", strerror(errno));
        return -1;
    }

    return 0;
}

// Send message to a queue waiting for a specific delay
int wm_sendmsg_ex(int usec, int queue, const char *message, const char *locmsg, char loc, bool (*fn_prd)()) {

#ifdef WIN32
    int msec = usec / 1000;
    Sleep(msec);
#else
    struct timeval timeout = {0, usec};
    select(0, NULL, NULL, NULL, &timeout);
#endif

    if (SendMSGPredicated(queue, message, locmsg, loc, fn_prd) < 0) {
        mdebug1("Unable to send message to queue: (%s)", strerror(errno));
        return -1;
    }

    return 0;
}
