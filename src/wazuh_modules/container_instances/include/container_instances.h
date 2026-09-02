/*
 * Wazuh Container Instances Security Module
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTAINER_INSTANCES_H
#define _CONTAINER_INSTANCES_H

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include <cJSON.h>

#ifdef __cplusplus
extern "C"
{
#endif

#include "commonDefs.h"

    /* Configuration JSON shape:
     * {
     *   "type": "kubernetes" | "docker",
     *   "kubernetes": { "kubeconfig": "...", "node_name": "...",
     *                   "ownership_poll_interval": 120,
     *                   "insecure_skip_tls_verify": false },
     *   "docker": { "socket_path": "/var/run/docker.sock" }
     * }
     */
    EXPORTED void container_instances_start(full_log_fnc_t callbackLog, const cJSON* configuration);

    EXPORTED void container_instances_stop(void);

#ifdef __cplusplus
}
#endif

typedef void (*container_instances_start_func)(full_log_fnc_t callbackLog, const cJSON* configuration);
typedef void (*container_instances_stop_func)(void);

#endif /* _CONTAINER_INSTANCES_H */
