/*
 * Wazuh Module for Kubernetes container monitoring connector
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_CONTAINER_CONNECTOR_H
#define WM_CONTAINER_CONNECTOR_H
#ifndef WIN32

#define WM_CONTAINER_CONNECTOR_LOGTAG ARGV0 ":container-connector"

#define WM_CONTAINER_CONNECTOR_DEF_TOKEN_PATH    "/var/run/secrets/kubernetes.io/serviceaccount/token"
#define WM_CONTAINER_CONNECTOR_DEF_CA_BUNDLE     "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
#define WM_CONTAINER_CONNECTOR_DEF_POLL_INTERVAL 60

typedef struct wm_container_connector_kubernetes_t {
    unsigned int enabled:1;
    unsigned int poll_interval;  /* seconds between pod list polls; 0 => use default */
    char *api_server;   /* https://host:port; empty => from $KUBERNETES_SERVICE_HOST */
    char *ca_bundle;    /* path; empty => default service-account ca.crt            */
    char *token_path;   /* path; empty => default service-account token              */
    char *node_name;    /* empty => $NODE_NAME                                       */
} wm_container_connector_kubernetes_t;

typedef struct wm_container_connector_docker_t {
    unsigned int enabled:1;
    unsigned int poll_interval;  /* seconds between snapshot + event resyncs; 0 => use default */
    char *socket_path;  /* empty => /var/run/docker.sock */
} wm_container_connector_docker_t;

typedef struct wm_container_connector_t {
    wm_container_connector_kubernetes_t kubernetes;
    wm_container_connector_docker_t     docker;
} wm_container_connector_t;

extern const wm_context WM_CONTAINER_CONNECTOR_CONTEXT;

int wm_container_connector_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

#endif
#endif
