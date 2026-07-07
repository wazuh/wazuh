/*
 * Wazuh Container Instances Security Module configuration parser
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#if defined(__linux__) && defined(CLIENT)

#include "wmodules.h"

static const char* CI_XML_ENABLED = "enabled";
static const char* CI_XML_TYPE = "type";
static const char* CI_XML_KUBERNETES = "kubernetes";
static const char* CI_XML_DOCKER = "docker";
static const char* CI_XML_KUBECONFIG = "kubeconfig";
static const char* CI_XML_NODE_NAME = "node_name";
static const char* CI_XML_OWNERSHIP_POLL_INTERVAL = "ownership_poll_interval";
static const char* CI_XML_INSECURE_SKIP_TLS_VERIFY = "insecure_skip_tls_verify";
static const char* CI_XML_SOCKET_PATH = "socket_path";

/* Invalid configurations disable the module but never abort agent startup
 * (fail closed). */
static void wm_container_instances_invalidate(wm_container_instances_t* config, const char* reason)
{
    merror("Invalid <container_instances> configuration: %s. Module disabled.", reason);
    config->enabled = 0;
}

static int wm_container_instances_parse_kubernetes(const OS_XML* xml, xml_node* node, wm_container_instances_t* config)
{
    xml_node** children = OS_GetElementsbyNode(xml, node);
    if (!children)
    {
        return 0;
    }

    for (int i = 0; children[i]; i++)
    {
        if (!children[i]->element || !children[i]->content)
        {
            continue;
        }
        if (strcmp(children[i]->element, CI_XML_KUBECONFIG) == 0)
        {
            os_free(config->kubernetes.kubeconfig);
            os_strdup(children[i]->content, config->kubernetes.kubeconfig);
        }
        else if (strcmp(children[i]->element, CI_XML_NODE_NAME) == 0)
        {
            os_free(config->kubernetes.node_name);
            os_strdup(children[i]->content, config->kubernetes.node_name);
        }
        else if (strcmp(children[i]->element, CI_XML_OWNERSHIP_POLL_INTERVAL) == 0)
        {
            char* end = NULL;
            const long value = strtol(children[i]->content, &end, 10);
            if (!end || *end != '\0' || value <= 0)
            {
                mwarn("Invalid <%s> value '%s'; keeping %d seconds.",
                      CI_XML_OWNERSHIP_POLL_INTERVAL,
                      children[i]->content,
                      config->kubernetes.ownership_poll_interval);
            }
            else if (value < WM_CONTAINER_INSTANCES_MIN_POLL_INTERVAL)
            {
                mwarn("<%s> below the minimum of %d seconds; clamping.",
                      CI_XML_OWNERSHIP_POLL_INTERVAL,
                      WM_CONTAINER_INSTANCES_MIN_POLL_INTERVAL);
                config->kubernetes.ownership_poll_interval = WM_CONTAINER_INSTANCES_MIN_POLL_INTERVAL;
            }
            else
            {
                config->kubernetes.ownership_poll_interval = (int)value;
            }
        }
        else if (strcmp(children[i]->element, CI_XML_INSECURE_SKIP_TLS_VERIFY) == 0)
        {
            const int value = w_parse_bool(children[i]->content);
            if (value < 0)
            {
                mwarn(
                    "Invalid <%s> value '%s'; expected yes/no.", CI_XML_INSECURE_SKIP_TLS_VERIFY, children[i]->content);
            }
            else
            {
                config->kubernetes.insecure_skip_tls_verify = (unsigned int)value;
            }
        }
        else
        {
            mwarn("Unknown <kubernetes> option '%s' in <container_instances>.", children[i]->element);
        }
    }

    OS_ClearNode(children);
    return 0;
}

static int wm_container_instances_parse_docker(const OS_XML* xml, xml_node* node, wm_container_instances_t* config)
{
    xml_node** children = OS_GetElementsbyNode(xml, node);
    if (!children)
    {
        return 0;
    }

    for (int i = 0; children[i]; i++)
    {
        if (!children[i]->element || !children[i]->content)
        {
            continue;
        }
        if (strcmp(children[i]->element, CI_XML_SOCKET_PATH) == 0)
        {
            os_free(config->docker_socket_path);
            os_strdup(children[i]->content, config->docker_socket_path);
        }
        else
        {
            mwarn("Unknown <docker> option '%s' in <container_instances>.", children[i]->element);
        }
    }

    OS_ClearNode(children);
    return 0;
}

int wm_container_instances_read(const OS_XML* xml, xml_node** nodes, wmodule* module)
{
    wm_container_instances_t* config = module->data;

    if (!config)
    {
        os_calloc(1, sizeof(wm_container_instances_t), config);
        config->enabled = 0; /* Opt-in module. */
        config->kubernetes.ownership_poll_interval = WM_CONTAINER_INSTANCES_DEF_POLL_INTERVAL;
        module->context = &WM_CONTAINER_INSTANCES_CONTEXT;
        module->tag = strdup(module->context->name);
        module->data = config;
    }

    if (!nodes)
    {
        return 0;
    }

    for (int i = 0; nodes[i]; i++)
    {
        if (!nodes[i]->element)
        {
            continue;
        }
        if (strcmp(nodes[i]->element, CI_XML_ENABLED) == 0)
        {
            const int value = w_parse_bool(nodes[i]->content);
            if (value < 0)
            {
                merror("Invalid <%s> value '%s' in <container_instances>.", CI_XML_ENABLED, nodes[i]->content);
                return OS_INVALID;
            }
            config->enabled = (unsigned int)value;
        }
        else if (strcmp(nodes[i]->element, CI_XML_TYPE) == 0)
        {
            if (nodes[i]->content &&
                (strcmp(nodes[i]->content, "kubernetes") == 0 || strcmp(nodes[i]->content, "docker") == 0))
            {
                os_free(config->type);
                os_strdup(nodes[i]->content, config->type);
            }
            else
            {
                wm_container_instances_invalidate(config, "<type> must be 'kubernetes' or 'docker'");
            }
        }
        else if (strcmp(nodes[i]->element, CI_XML_KUBERNETES) == 0)
        {
            wm_container_instances_parse_kubernetes(xml, nodes[i], config);
        }
        else if (strcmp(nodes[i]->element, CI_XML_DOCKER) == 0)
        {
            wm_container_instances_parse_docker(xml, nodes[i], config);
        }
        else
        {
            mwarn("Unknown option '%s' in <container_instances>.", nodes[i]->element);
        }
    }

    if (config->enabled)
    {
        if (!config->type)
        {
            wm_container_instances_invalidate(config, "<type> is required");
        }
        else if (strcmp(config->type, "kubernetes") == 0 &&
                 (!config->kubernetes.kubeconfig || !config->kubernetes.node_name))
        {
            wm_container_instances_invalidate(config, "type=kubernetes requires <kubeconfig> and <node_name>");
        }
    }

    return 0;
}

int Read_ContainerInstances(const OS_XML* xml, xml_node* node, void* d1)
{
    wmodule** wmodules = (wmodule**)d1;
    wmodule* cur_wmodule = NULL;

    /* Reuse an existing node for this module (agent.conf overrides) or append
     * a new one, mirroring Read_SCA. */
    if ((cur_wmodule = *wmodules))
    {
        wmodule* found = NULL;
        for (wmodule* it = *wmodules; it; it = it->next)
        {
            if (it->tag && strcmp(it->tag, CONTAINER_INSTANCES_WM_NAME) == 0)
            {
                found = it;
                break;
            }
        }
        if (found)
        {
            cur_wmodule = found;
        }
        else
        {
            while (cur_wmodule->next)
            {
                cur_wmodule = cur_wmodule->next;
            }
            os_calloc(1, sizeof(wmodule), cur_wmodule->next);
            cur_wmodule = cur_wmodule->next;
        }
    }
    else
    {
        os_calloc(1, sizeof(wmodule), cur_wmodule);
        *wmodules = cur_wmodule;
    }

    xml_node** children = OS_GetElementsbyNode(xml, node);
    const int result = wm_container_instances_read(xml, children, cur_wmodule);
    OS_ClearNode(children);
    return result;
}

#endif /* __linux__ && CLIENT */
