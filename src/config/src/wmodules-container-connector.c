/*
 * Wazuh Module Configuration — container-connector (Kubernetes)
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32

#include "wmodules.h"

static const char *XML_KUBERNETES = "kubernetes";
static const char *XML_ENABLED    = "enabled";
static const char *XML_API_SERVER = "api_server";
static const char *XML_CA_BUNDLE  = "ca_bundle";
static const char *XML_TOKEN_PATH = "token_path";
static const char *XML_NODE_NAME  = "node_name";

static int parse_kubernetes_block(const OS_XML *xml, xml_node *kub_node, wm_container_connector_kubernetes_t *out) {
    xml_node **children = OS_GetElementsbyNode(xml, kub_node);
    if (!children) {
        mdebug1("Empty <kubernetes> block in <container_connector>; using defaults.");
        return 0;
    }

    int rc = 0;
    for (int i = 0; children[i]; i++) {
        if (!children[i]->element) {
            merror(XML_ELEMNULL);
            rc = OS_INVALID;
            break;
        } else if (!strcmp(children[i]->element, XML_ENABLED)) {
            if (!strcmp(children[i]->content, "yes")) {
                out->enabled = 1;
            } else if (!strcmp(children[i]->content, "no")) {
                out->enabled = 0;
            } else {
                merror("At module '%s/%s': invalid content for tag '%s'.",
                       WM_CONTAINER_CONNECTOR_CONTEXT.name, XML_KUBERNETES, XML_ENABLED);
                rc = OS_INVALID;
                break;
            }
        } else if (!strcmp(children[i]->element, XML_API_SERVER)) {
            os_free(out->api_server);
            if (children[i]->content && *children[i]->content) os_strdup(children[i]->content, out->api_server);
        } else if (!strcmp(children[i]->element, XML_CA_BUNDLE)) {
            os_free(out->ca_bundle);
            if (children[i]->content && *children[i]->content) os_strdup(children[i]->content, out->ca_bundle);
        } else if (!strcmp(children[i]->element, XML_TOKEN_PATH)) {
            os_free(out->token_path);
            if (children[i]->content && *children[i]->content) os_strdup(children[i]->content, out->token_path);
        } else if (!strcmp(children[i]->element, XML_NODE_NAME)) {
            os_free(out->node_name);
            if (children[i]->content && *children[i]->content) os_strdup(children[i]->content, out->node_name);
        } else {
            merror("No such tag '%s' at module '%s/%s'.",
                   children[i]->element, WM_CONTAINER_CONNECTOR_CONTEXT.name, XML_KUBERNETES);
            rc = OS_INVALID;
            break;
        }
    }

    OS_ClearNode(children);
    return rc;
}

int wm_container_connector_read(const OS_XML *xml, xml_node **nodes, wmodule *module) {
    wm_container_connector_t *cfg = NULL;

    os_calloc(1, sizeof(wm_container_connector_t), cfg);
    cfg->kubernetes.enabled = 1;
    module->context = &WM_CONTAINER_CONNECTOR_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = cfg;

    if (!nodes) return 0;

    for (int i = 0; nodes[i]; i++) {
        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_KUBERNETES)) {
            if (parse_kubernetes_block(xml, nodes[i], &cfg->kubernetes) < 0) {
                return OS_INVALID;
            }
        } else {
            merror("No such tag '%s' at module '%s'.", nodes[i]->element, WM_CONTAINER_CONNECTOR_CONTEXT.name);
            return OS_INVALID;
        }
    }

    return 0;
}

int Read_ContainerConnector(const OS_XML *xml, xml_node *node, void *d1) {
    wmodule **wmodules = (wmodule **)d1;
    wmodule *cur_wmodule;
    xml_node **children = NULL;

    /* Allocate or reuse module slot in the list */
    if ((cur_wmodule = *wmodules) != NULL) {
        wmodule *existing = *wmodules;
        int found = 0;
        while (existing) {
            if (existing->tag && !strcmp(existing->tag, WM_CONTAINER_CONNECTOR_CONTEXT.name)) {
                cur_wmodule = existing;
                found = 1;
                break;
            }
            existing = existing->next;
        }
        if (!found) {
            while (cur_wmodule->next) cur_wmodule = cur_wmodule->next;
            os_calloc(1, sizeof(wmodule), cur_wmodule->next);
            cur_wmodule = cur_wmodule->next;
        }
    } else {
        *wmodules = cur_wmodule = calloc(1, sizeof(wmodule));
    }

    if (!cur_wmodule) {
        merror(MEM_ERROR, errno, strerror(errno));
        return OS_INVALID;
    }

    if ((children = OS_GetElementsbyNode(xml, node)) == NULL) {
        mdebug1("Empty configuration for module '%s'", WM_CONTAINER_CONNECTOR_CONTEXT.name);
    }

    int rc = wm_container_connector_read(xml, children, cur_wmodule);
    OS_ClearNode(children);
    return rc;
}

#endif /* !WIN32 */
