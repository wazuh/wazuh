#ifndef SOCKET_FORWARDER_H
#define SOCKET_FORWARDER_H

#include <time.h>

/* Common structure for socket forwarding in modulesd and logcollector */
typedef struct _socket_forwarder {
    char   *name;
    char   *location;
    int    mode;
    char   *prefix;
    int    socket;
    time_t last_attempt;
} socket_forwarder;

#endif /* SOCKET_FORWARDER_H */
