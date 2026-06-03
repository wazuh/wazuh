/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef READ_KUBERNETES_H
#define READ_KUBERNETES_H

#ifndef WIN32

#include "shared.h"
#include "localfile-config.h"

/**
 * @brief Logcollector reader for &lt;localfile&gt; with &lt;location&gt;kubernetes...&lt;/location&gt;.
 *
 * Each invocation:
 *   1. Scans /var/log/pods/ to detect pods present on the node.
 *   2. For each pod, resolves the K8s container metadata via the
 *      container-connector IPC (/var/ossec/queue/sockets/container_connector).
 *   3. Applies the &lt;filter&gt; rules of the localfile config (AND-combined:
 *      container_name, image_name, namespace, pod_name, label).
 *   4. For matched containers, tracks log files and (T-K7.3+) tails them
 *      with rotation handling. For T-K7.2 the function only logs the
 *      detection and tracks the active set; tailing is deferred.
 *
 * State is owned by w_k8s_log_config_t::runtime, allocated on the first call.
 */
void *read_kubernetes(logreader *lf, int *rc, int drop_it);

/**
 * @brief Free the runtime state held by a K8s logreader. Safe to call with
 * lf == NULL or lf->k8s_log == NULL.
 */
void k8s_logreader_destroy_runtime(logreader *lf);

#endif /* !WIN32 */
#endif /* READ_KUBERNETES_H */
