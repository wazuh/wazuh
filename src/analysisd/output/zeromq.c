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
#if CZMQ_VERSION_MAJOR == 2
static zctx_t *zeromq_context;
static void *zeromq_pubsocket;
#elif CZMQ_VERSION_MAJOR >= 3
zsock_t *zeromq_pubsocket;
zactor_t *auth;
#endif

#if CZMQ_VERSION_MAJOR == 2
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
#elif CZMQ_VERSION_MAJOR >= 3
void zeromq_output_start(const char *uri, const char *client_cert_path, const char *server_cert_path)
{
    int rc;

    debug1("%s: DEBUG: New ZeroMQ Socket: ZMQ_PUB", ARGV0);
    zeromq_pubsocket = zsock_new(ZMQ_PUB);
    if (zeromq_pubsocket == NULL) {
        merror("%s: Unable to initialize ZeroMQ Socket", ARGV0);
        return;
    }

    if (zsys_has_curve()) {
        if (client_cert_path && server_cert_path) {
            debug1("%s: DEBUG: Initiating CURVE for ZeroMQ Socket", ARGV0);
            auth = zactor_new(zauth, NULL);
            if (!auth) {
                merror("%s: Unable to start auth for ZeroMQ Sock", ARGV0);
            }
            zstr_sendx(auth, "CURVE", client_cert_path, NULL);
            zsock_wait(auth);

            zcert_t *server_cert = zcert_load(server_cert_path);
            if (!server_cert) {
                merror("%s: Unable to load server certificate: %s.", ARGV0, server_cert_path);
            }

            zcert_apply(server_cert, zeromq_pubsocket);
            zsock_set_curve_server(zeromq_pubsocket, 1);

            zcert_destroy(&server_cert);
        }
    }

    debug1("%s: DEBUG: Listening on ZeroMQ Socket: %s", ARGV0, uri);
    rc = zsock_bind(zeromq_pubsocket, "%s", uri);
    if (rc) {
        merror("%s: Unable to bind the ZeroMQ Socket: %s.", ARGV0, uri);
        return;
    }
}
#endif

#if CZMQ_VERSION_MAJOR == 2
void zeromq_output_end()
{
    zsocket_destroy(zeromq_context, zeromq_pubsocket);
    zctx_destroy(&zeromq_context);
}
#elif CZMQ_VERSION_MAJOR >= 3
void zeromq_output_end()
{
    zsock_destroy(&zeromq_pubsocket);
    zactor_destroy(&auth);
}
#endif

#if CZMQ_VERSION_MAJOR == 2
void zeromq_output_event(const Eventinfo *lf)
{
    char *json_alert = Eventinfo_to_jsonstr(lf);

    zmsg_t *msg = zmsg_new();
    zmsg_addstr(msg, "ossec.alerts");
    zmsg_addstr(msg, json_alert);
    zmsg_send(&msg, zeromq_pubsocket);
    free(json_alert);
}
#elif ZMQ_VERSION_MAJOR >= 3
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

#endif
