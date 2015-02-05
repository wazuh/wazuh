/* Copyright (C) 2015 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef ZEROMQ_OUTPUT_ENABLED

#include "zeromq.h"

#include "shared.h"
#include "rules.h"
#include "czmq.h"
#include "format/to_json.h"


/* Global variables */
static zctx_t *zeromq_context;
static void *zeromq_pubsocket;


void zeromq_output_start(const char *uri)
{
    int rc;

    debug1("%s: DEBUG: New ZeroMQ Context", ARGV0);
    zeromq_context = zctx_new();
    if (zeromq_context == NULL) {
        merror("%s: Unable to initialize ZeroMQ library", ARGV0);
        return;
    }

    debug1("%s: DEBUG: New ZeroMQ Socket: ZMQ_PUB", ARGV0);
    zeromq_pubsocket = zsocket_new(zeromq_context, ZMQ_PUB);
    if (zeromq_pubsocket == NULL) {
        merror("%s: Unable to initialize ZeroMQ Socket", ARGV0);
        return;
    }

    debug1("%s: DEBUG: Listening on ZeroMQ Socket: %s", ARGV0, uri);
    rc = zsocket_bind(zeromq_pubsocket, "%s", uri);
    if (rc) {
        merror("%s: Unable to bind the ZeroMQ Socket: %s.", ARGV0, uri);
        return;
    }
}

void zeromq_output_end()
{
    zsocket_destroy(zeromq_context, zeromq_pubsocket);
    zctx_destroy(&zeromq_context);
}

void zeromq_output_event(const Eventinfo *lf)
{
    char *json_alert = Eventinfo_to_jsonstr(lf);

    zmsg_t *msg = zmsg_new();
    zmsg_addstr(msg, "ossec.alerts");
    zmsg_addstr(msg, json_alert);
    zmsg_send(&msg, zeromq_pubsocket);
    free(json_alert);
}

#endif

