/*
 * Cluster settings manager
 * Copyright (C) 2015-2019, Wazuh Inc.
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


int Read_Cluster(const OS_XML *xml, XML_NODE node, void *d1, __attribute__((unused)) void *d2, char **output) {

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

    _Config *Config;
    Config = (_Config *)d1;
    int i;
    int disable_cluster_info = 0;
    char message[OS_FLSIZE];
    int found = 0;

    Config->hide_cluster_info = 0;

    if (output){
        if (Config->cluster_name)
            free(Config->cluster_name);
        if (Config->node_name)
            free(Config->node_name);
        if (Config->node_type)
            free(Config->node_type);
    }

    for (i = 0; node[i]; i++) {
        if (!node[i]->element) {
            if (output == NULL) {
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            return OS_INVALID;
        } else if (!node[i]->content) {
            if (output == NULL) {
                merror(XML_VALUENULL, node[i]->element);
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid NULL content for element: %s.",
                    node[i]->element);
                wm_strcat(output, message, '\n');
            }
            return OS_INVALID;
        } else if (!strcmp(node[i]->element, cluster_name)) {
            if (!strlen(node[i]->content)) {
                if (output == NULL) {
                    merror("Cluster name is empty in configuration.");
                } else {
                    wm_strcat(output, "Cluster name is empty in configuration.", '\n');
                }
                return OS_INVALID;
            } else if (strspn(node[i]->content, C_VALID) < strlen(node[i]->content)) {
                if (output == NULL) {
                    merror("Detected a not allowed character in cluster name: \"%s\". Characters allowed: \"%s\".", node[i]->content, C_VALID);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Detected a not allowed character in cluster name: \"%s\". Characters allowed: \"%s\".",
                        node[i]->content, C_VALID);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }
            if (Config->cluster_name) {
                free(Config->cluster_name);
            }
            os_strdup(node[i]->content, Config->cluster_name);
        } else if (!strcmp(node[i]->element, node_name)) {
            if (!strlen(node[i]->content)) {
                if (output == NULL) {
                    merror("Node name is empty in configuration.");
                } else {
                    wm_strcat(output, "Node name is empty in configuration.", '\n');
                }
                return OS_INVALID;
            } else if (strspn(node[i]->content, C_VALID) < strlen(node[i]->content)) {
                if (output == NULL) {
                    merror("Detected a not allowed character in node name: \"%s\". Characters allowed: \"%s\".", node[i]->content, C_VALID);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Detected a not allowed character in node name: \"%s\". Characters allowed: \"%s\".",
                        node[i]->content, C_VALID);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }
            if (Config->node_name) {
                free(Config->node_name);
            }
            os_strdup(node[i]->content, Config->node_name);
        } else if (!strcmp(node[i]->element, node_type)) {
            if (!strlen(node[i]->content)) {
                if (output == NULL) {
                    merror("Node type is empty in configuration.");
                } else {
                    wm_strcat(output, "Node type is empty in configuration.", '\n');
                }
                return OS_INVALID;
            } else if (strcmp(node[i]->content, "worker") && strcmp(node[i]->content, "client") && strcmp(node[i]->content, "master") )  {
                if (output == NULL) {
                    merror("Detected a not allowed node type '%s'. Valid types are 'master' and 'worker'.", node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Detected a not allowed node type '%s'. Valid types are 'master' and 'worker'.",
                        node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }
            if (Config->node_type) {
                os_free(Config->node_type);
            }
            os_strdup(node[i]->content, Config->node_type);
        } else if (!strcmp(node[i]->element, key)) {
            if (output) {
                if (strlen(node[i]->content) == 0) {
                    snprintf(message, OS_FLSIZE, "Unspecified key");
                    found = 1;
                } else if (strlen(node[i]->content) !=	32) {
                    snprintf(message, OS_FLSIZE, "Key must be 32 characters long and only have alphanumeric characters");
                    found = 1;
                }
            }
        } else if (!strcmp(node[i]->element, socket_timeout)) {
        } else if (!strcmp(node[i]->element, connection_timeout)) {
        } else if (!strcmp(node[i]->element, disabled)) {
            if (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no")) {
                if (!output) {
                    merror("Detected a not allowed value for disabled tag '%s'. Valid values are 'yes' and 'no'.", node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Detected a not allowed value for disabled tag '%s'. Valid values are 'yes' and 'no'.",
                        node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            } if (strcmp(node[i]->content, "yes") && output) {
                if (found) {
                    wm_strcat(output, message, '\n');
                    if (found == 1)
                        return OS_INVALID;
                }
            }
            if (strcmp(node[i]->content, "yes") == 0) {
                disable_cluster_info = 1;
            }
        } else if (!strcmp(node[i]->element, hidden)) {
            if (strcmp(node[i]->content, "yes") == 0) {
                Config->hide_cluster_info = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                Config->hide_cluster_info = 0;
            } else if (output == NULL) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid value for element '%s': %s.",
                    node[i]->element, node[i]->content);
                wm_strcat(output, message, '\n');
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, interval)) {
            if (!output){
                mwarn("Detected a deprecated configuration for cluster. Interval option is not longer available.");
            } else {
                wm_strcat(output, "WARNING: Detected a deprecated configuration for cluster. Interval option is not longer available.", '\n');
            }
        } else if (!strcmp(node[i]->element, nodes)) {
            if (output) {
                
                /* Get children */
                xml_node **children = NULL;
                    if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
                }

                int  j;
                for (j = 0; children[j]; j++) {
                    if (strcmp(children[j]->element, "node") == 0) {
                        if (!strcmp(children[j]->content, "localhost") || !strcmp(children[j]->content, "NODE_IP") ||
                                !strcmp(children[j]->content, "0.0.0.0") || !strcmp(children[j]->content, "127.0.1.1")) {
                            snprintf(message, OS_FLSIZE, "Invalid elements in node fields: %s.", children[j]->content);
                            found = 1;
                        }
                        if ((j > 0) && (!found)) {
                            snprintf(message, OS_FLSIZE,
                                "WARNING: Found more than one node in configuration. Only master node should be specified. Using as master %s",
                                children[0]->content);
                                found = 2;
                        }
                    }
                }
                OS_ClearNode(children);
            }
        } else if (!strcmp(node[i]->element, port)) {
            if (output) {
                int port_var = atoi(node[i]->content);
                if ((port_var < 1024) || (port_var > 65535)) {
                    snprintf(message, OS_FLSIZE, "Port must be higher than 1024 and lower than 65535.");
                    found = 1;
                }
            }
        } else if (!strcmp(node[i]->element, bind_addr)) {
        } else if (output == NULL) {
            merror(XML_INVELEM, node[i]->element);
            return OS_INVALID;
        } else {
            snprintf(message, OS_FLSIZE,
                "Invalid element in the configuration: '%s'.",
                node[i]->content);
            wm_strcat(output, message, '\n');
            return OS_INVALID;
        }
    }

    if (disable_cluster_info)
        Config->hide_cluster_info = 1;

    return 0;
 }
