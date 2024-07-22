/*
 * Cluster settings manager
 * Copyright (C) 2015, Wazuh Inc.
 * Oct 16, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "config.h"
#include "global-config.h"


int Read_Cluster(const OS_XML *xml, XML_NODE node, void *d1, __attribute__((unused)) void *d2) {

    static const char *disabled = "disabled";
    static const char *cluster_name = "name";
    static const char *node_name = "node_name";
    static const char *node_type = "node_type";
    static const char *key = "key";
    static const char *socket_timeout = "socket_timeout";
    static const char *connection_timeout = "connection_timeout";
    static const char *interval = "interval";
    static const char *nodes = "nodes";
    static const char *hidden = "hidden";
    static const char *port = "port";
    static const char *bind_addr = "bind_addr";
    static const char *C_VALID = "!\"#$%&'-.0123456789:<=>?ABCDEFGHIJKLMNOPQRESTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}~";

    xml_node **child = NULL;
    static const char *haproxy_helper = "haproxy_helper";
    static const char *haproxy_disabled = "haproxy_disabled";
    static const char *haproxy_address = "haproxy_address";
    static const char *haproxy_port = "haproxy_port";
    static const char *haproxy_protocol = "haproxy_protocol";
    static const char *haproxy_user = "haproxy_user";
    static const char *haproxy_password = "haproxy_password";
    static const char *haproxy_resolver = "haproxy_resolver";
    static const char *haproxy_backend = "haproxy_backend";
    static const char *haproxy_cert = "haproxy_cert";
    static const char *client_cert = "client_cert";
    static const char *client_cert_key = "client_cert_key";
    static const char *client_cert_password = "client_cert_password";
    static const char *api_port = "api_port";
    static const char *excluded_nodes = "excluded_nodes";
    static const char *frequency = "frequency";
    static const char *agent_chunk_size = "agent_chunk_size";
    static const char *agent_reconnection_time = "agent_reconnection_time";
    static const char *agent_reconnection_stability_time = "agent_reconnection_stability_time";
    static const char *imbalance_tolerance = "imbalance_tolerance";
    static const char *remove_disconnected_node_after = "remove_disconnected_node_after";

    _Config *Config;
    Config = (_Config *)d1;
    int i;
    int j;
    int disable_cluster_info = 0;

    Config->hide_cluster_info = 0;

    for (i = 0; node[i]; i++) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return OS_INVALID;
        } else if (!strcmp(node[i]->element, cluster_name)) {
            if (!strlen(node[i]->content)) {
                merror("Cluster name is empty in configuration");
                return OS_INVALID;
            } else if (strspn(node[i]->content, C_VALID) < strlen(node[i]->content)) {
                merror("Detected a not allowed character in cluster name: \"%s\". Characters allowed: \"%s\".", node[i]->content, C_VALID);
                return OS_INVALID;
            }
            os_strdup(node[i]->content, Config->cluster_name);
        } else if (!strcmp(node[i]->element, node_name)) {
            if (!strlen(node[i]->content)) {
                merror("Node name is empty in configuration");
                return OS_INVALID;
            } else if (strspn(node[i]->content, C_VALID) < strlen(node[i]->content)) {
                merror("Detected a not allowed character in node name: \"%s\". Characters allowed: \"%s\".", node[i]->content, C_VALID);
                return OS_INVALID;
            }
            os_strdup(node[i]->content, Config->node_name);
        } else if (!strcmp(node[i]->element, node_type)) {
            if (!strlen(node[i]->content)) {
                merror("Node type is empty in configuration");
                return OS_INVALID;
            } else if (strcmp(node[i]->content, "worker") && strcmp(node[i]->content, "client") && strcmp(node[i]->content, "master") )  {
                merror("Detected a not allowed node type '%s'. Valid types are 'master' and 'worker'.", node[i]->content);
                return OS_INVALID;
            }
            os_strdup(node[i]->content, Config->node_type);
        } else if (!strcmp(node[i]->element, key)) {
        } else if (!strcmp(node[i]->element, socket_timeout)) {
        } else if (!strcmp(node[i]->element, connection_timeout)) {
        } else if (!strcmp(node[i]->element, disabled)) {
            if (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no")) {
                merror("Detected a not allowed value for disabled tag '%s'. Valid values are 'yes' and 'no'.", node[i]->content);
                return OS_INVALID;
            }
            if (strcmp(node[i]->content, "yes") == 0) {
                disable_cluster_info = 1;
            }
        } else if (!strcmp(node[i]->element, hidden)) {
            if (strcmp(node[i]->content, "yes") == 0) {
                Config->hide_cluster_info = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                Config->hide_cluster_info = 0;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, interval)) {
            mwarn("Detected a deprecated configuration for cluster. Interval option is not longer available.");
        } else if (!strcmp(node[i]->element, nodes)) {
        } else if (!strcmp(node[i]->element, port)) {
        } else if (!strcmp(node[i]->element, bind_addr)) {
        } else if (!strcmp(node[i]->element, haproxy_helper)) {

            if (!(child = OS_GetElementsbyNode(xml, node[i]))) {
                continue;
            }

            for (j = 0; child[j]; j++) {
                if (!strcmp(child[j]->element, haproxy_disabled)) {
                    if (strcmp(child[j]->content, "yes") && strcmp(child[j]->content, "no")) {
                        merror("Detected an invalid value for the disabled tag '%s'. Valid values are 'yes' and 'no'.", child[j]->element);
                        OS_ClearNode(child);
                        return OS_INVALID;
                    }
                } else if (!strcmp(child[j]->element, frequency)) {
                } else if (!strcmp(child[j]->element, haproxy_address)) {
                    if (!strlen(node[i]->content)) {
                        merror("HAProxy address is missing in the configuration");
                        OS_ClearNode(child);
                        return OS_INVALID;
                    }
                } else if (!strcmp(child[j]->element, haproxy_port)) {
                } else if (!strcmp(child[j]->element, haproxy_protocol)) {
                    if (strcmp(child[j]->content, "http") && strcmp(child[j]->content, "https")) {
                        merror("Detected an invalid value for the haproxy_protocol tag '%s'. Valid values are 'http' and 'https'.", child[j]->element);
                        OS_ClearNode(child);
                        return OS_INVALID;
                    }
                } else if (!strcmp(child[j]->element, haproxy_user)) {
                    if (!strlen(node[i]->content)) {
                        merror("HAProxy user is missing in the configuration");
                        OS_ClearNode(child);
                        return OS_INVALID;
                    }
                } else if (!strcmp(child[j]->element, haproxy_password)) {
                    if (!strlen(node[i]->content)) {
                        merror("HAProxy password is missing in the configuration");
                        OS_ClearNode(child);
                        return OS_INVALID;
                    }
                } else if (!strcmp(child[j]->element, haproxy_cert)) {
                } else if (!strcmp(child[j]->element, client_cert)) {
                } else if (!strcmp(child[j]->element, client_cert_key)) {
                } else if (!strcmp(child[j]->element, client_cert_password)) {
                } else if (!strcmp(child[j]->element, haproxy_backend)) {
                } else if (!strcmp(child[j]->element, haproxy_resolver)) {
                } else if (!strcmp(child[j]->element, excluded_nodes)) {
                } else if (!strcmp(child[j]->element, agent_chunk_size)) {
                } else if (!strcmp(child[j]->element, agent_reconnection_time)) {
                } else if (!strcmp(child[j]->element, agent_reconnection_stability_time)) {
                } else if (!strcmp(child[j]->element, imbalance_tolerance)) {
                } else if (!strcmp(child[j]->element, remove_disconnected_node_after)) {
                } else {
                    merror(XML_INVELEM, child[i]->element);
                    OS_ClearNode(child);
                    return OS_INVALID;
                }

            }
    } else {
        merror(XML_INVELEM, node[i]->element);
        return OS_INVALID;
    }


    if (disable_cluster_info)
        Config->hide_cluster_info = 1;

    }
    return 0;
}
