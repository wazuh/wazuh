
#ifdef ZEROMQ_OUTPUT

#include "shared.h"
#include "eventinfo.h"
#include "shared.h"
#include "rules.h"
#include "czmq.h"
#include "format/to_json.h"
//#include "zeromq_output.h"
#include "zeromq.h"




static zctx_t *zeromq_context;
static void *zeromq_pubsocket; 


void zeromq_output_start(char *uri, int argc, char **argv) {

    int rc;

    /* -Werror causes gcc to bail because these are defined but not used.*/
    if(!argc) { }	// XXX stupid hack
    if(!argv) { }	// XXX stupid hack

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
    rc = zsocket_bind(zeromq_pubsocket, uri);
    if (rc) {
        merror("%s: Unable to bind the ZeroMQ Socket: %s.", ARGV0, uri);
        return;
    }


}

void zeromq_output_end() {
    zsocket_destroy(zeromq_context, zeromq_pubsocket);
    zctx_destroy(&zeromq_context);
}


void zeromq_output_event(Eventinfo *lf){
    char *json_alert = Eventinfo_to_jsonstr(lf);
    zmsg_t *msg = zmsg_new();
    zmsg_addstr(msg, "ossec.alerts");
    zmsg_addstr(msg, json_alert);
    zmsg_send(&msg, zeromq_pubsocket);
    free(json_alert);
}








#endif
