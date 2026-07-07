/*
 * Wazuh Container Instances Security Module
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_CONTAINER_INSTANCES_H
#define WM_CONTAINER_INSTANCES_H

#define CONTAINER_INSTANCES_WM_NAME   "container-instances"
#define WM_CONTAINER_INSTANCES_LOGTAG ARGV0 ":" CONTAINER_INSTANCES_WM_NAME

#define WM_CONTAINER_INSTANCES_DEF_POLL_INTERVAL 120
#define WM_CONTAINER_INSTANCES_MIN_POLL_INTERVAL 30
#define WM_CONTAINER_INSTANCES_DEF_DOCKER_SOCKET "/var/run/docker.sock"

typedef struct wm_container_instances_kubernetes_t
{
    char* kubeconfig;
    char* node_name;
    int ownership_poll_interval;
    unsigned int insecure_skip_tls_verify : 1;
} wm_container_instances_kubernetes_t;

typedef struct wm_container_instances_t
{
    unsigned int enabled : 1;
    char* type; /* "kubernetes" | "docker" */
    wm_container_instances_kubernetes_t kubernetes;
    char* docker_socket_path;
} wm_container_instances_t;

extern const wm_context WM_CONTAINER_INSTANCES_CONTEXT;

int wm_container_instances_read(const OS_XML* xml, xml_node** nodes, wmodule* module);

#endif /* WM_CONTAINER_INSTANCES_H */
