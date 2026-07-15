/*
 * Wazuh container-connector module — C API exported by libcontainer_connector.so
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTAINER_CONNECTOR_H
#define _CONTAINER_CONNECTOR_H

#ifdef _WIN32
#  ifdef WIN_EXPORT
#    define EXPORTED __declspec(dllexport)
#  else
#    define EXPORTED __declspec(dllimport)
#  endif
#elif __GNUC__ >= 4
#  define EXPORTED __attribute__((visibility("default")))
#else
#  define EXPORTED
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "logging_helper.h"

/* Self-contained configuration view consumed by the lib. The wazuh-modulesd
 * glue translates from its own struct into this one to keep the lib decoupled
 * from modulesd internals. */
typedef struct cc_kubernetes_config_t {
    int         enabled;
    int         poll_interval; /* seconds between pod list polls; 0 => use built-in default (5s). */
    const char* api_server;   /* NULL or empty => derived from $KUBERNETES_SERVICE_HOST/PORT. */
    const char* ca_bundle;    /* NULL or empty => default service-account ca.crt path.       */
    const char* token_path;   /* NULL or empty => default service-account token path.        */
    const char* node_name;    /* NULL or empty => derived from $NODE_NAME.                   */
} cc_kubernetes_config_t;

typedef struct cc_docker_config_t {
    int         enabled;
    int         poll_interval; /* seconds between snapshot + event resyncs; 0 => use built-in default (60s). */
    const char* socket_path;  /* NULL or empty => /var/run/docker.sock */
} cc_docker_config_t;

typedef struct cc_config_t {
    cc_kubernetes_config_t kubernetes;
    cc_docker_config_t     docker;
} cc_config_t;

typedef void (*cc_log_callback_t)(modules_log_level_t level, const char* log, const char* tag);

/* Inject the logging callback. Must be called before cc_init(). */
EXPORTED void cc_set_log_function(cc_log_callback_t cb);

/* Build the C++ side from the parsed configuration. Safe to call only once
 * per lifecycle; subsequent calls without an intervening cc_stop() are no-ops. */
EXPORTED void cc_init(const cc_config_t* cfg);

/* Spawn worker threads and start servicing K8s events. */
EXPORTED void cc_start(void);

/* Block the calling thread until cc_stop() is observed (externally or due to
 * an internal fatal error). Returns immediately if not initialised. */
EXPORTED void cc_wait_for_shutdown(void);

/* Tear down every resource owned by the module. Idempotent and safe from
 * within signal handlers ONLY indirectly (do not call from a signal handler;
 * have the main thread call it after observing the shutdown flag). */
EXPORTED void cc_stop(void);

#ifdef __cplusplus
}
#endif

/* Function-pointer typedefs to enable dlsym-based loading if desired. */
typedef void (*cc_set_log_function_func)(cc_log_callback_t cb);
typedef void (*cc_init_func)(const cc_config_t* cfg);
typedef void (*cc_start_func)(void);
typedef void (*cc_wait_for_shutdown_func)(void);
typedef void (*cc_stop_func)(void);

#endif /* _CONTAINER_CONNECTOR_H */
