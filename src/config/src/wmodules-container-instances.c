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
#include "wm_container_instances.h"

/* Configuration surface (HLD "Container Instances Security", section 4):
 *
 *   <container_security>
 *     <container_instances>
 *       <enabled>yes</enabled>
 *       <type>docker</type>
 *       <socket_path>/var/run/docker.sock</socket_path>
 *     </container_instances>
 *     <container_instances>
 *       <enabled>yes</enabled>
 *       <type>kubernetes</type>
 *       <kubeconfig>/etc/wazuh-agent/container_instances/kubeconfig</kubeconfig>
 *       <node_name>container-node-1</node_name>
 *       <ownership_poll_interval>120</ownership_poll_interval>
 *       <insecure_skip_tls_verify>no</insecure_skip_tls_verify>
 *     </container_instances>
 *   </container_security>
 *
 * One <container_instances> block per runtime integration, discriminated by
 * <type>. Repeating the block is how dual-runtime monitoring is expressed: a
 * Kubernetes node with a host Docker daemon beside it is the supported
 * topology (#37382), and a single <type> on a single block could not say it.
 *
 * The runtime's own options are children of its block rather than of a nested
 * <docker>/<kubernetes> element -- <type> already identifies the runtime, so a
 * second level would only repeat it.
 */
static const char* CI_XML_CONTAINER_INSTANCES = "container_instances";
static const char* CI_XML_ENABLED = "enabled";
static const char* CI_XML_TYPE = "type";
static const char* CI_XML_TYPE_KUBERNETES = "kubernetes";
static const char* CI_XML_TYPE_DOCKER = "docker";
static const char* CI_XML_KUBECONFIG = "kubeconfig";
static const char* CI_XML_NODE_NAME = "node_name";
static const char* CI_XML_OWNERSHIP_POLL_INTERVAL = "ownership_poll_interval";
static const char* CI_XML_INSECURE_SKIP_TLS_VERIFY = "insecure_skip_tls_verify";
static const char* CI_XML_SOCKET_PATH = "socket_path";
static const char* CI_XML_SYSCOLLECTOR = "syscollector";
static const char* CI_XML_INTERVAL = "interval";
/* syscheckd's half of <container_security>, parsed by Read_ContainerSecuritySyscheck.
 * Named here so this reader steps over it instead of warning about it. */
static const char* CI_XML_SYSCHECK = "syscheck";

/* Invalid configurations disable the module but never abort agent startup
 * (fail closed). */
static void wm_container_instances_invalidate(wm_container_instances_t* config, const char* reason)
{
    merror("Invalid <container_security> configuration: %s. Module disabled.", reason);
    config->enabled = 0;
    config->kubernetes_present = 0;
    config->docker_present = 0;
    config->invalid = 1;
}

/* yes/no is the Wazuh convention and stays canonical; true/false is accepted
 * because the HLD writes <enabled>true</enabled> and rejecting it would turn a
 * copy-paste of the published example into a silently disabled module. */
static int wm_container_instances_parse_bool(const char* content)
{
    if (!content)
    {
        return -1;
    }
    const int value = w_parse_bool(content);
    if (value >= 0)
    {
        return value;
    }
    if (strcmp(content, "true") == 0)
    {
        return 1;
    }
    if (strcmp(content, "false") == 0)
    {
        return 0;
    }
    return -1;
}

static void wm_container_instances_parse_kubernetes_option(xml_node* child, wm_container_instances_t* config)
{
    if (strcmp(child->element, CI_XML_KUBECONFIG) == 0)
    {
        os_free(config->kubernetes.kubeconfig);
        os_strdup(child->content, config->kubernetes.kubeconfig);
    }
    else if (strcmp(child->element, CI_XML_NODE_NAME) == 0)
    {
        os_free(config->kubernetes.node_name);
        os_strdup(child->content, config->kubernetes.node_name);
    }
    else if (strcmp(child->element, CI_XML_OWNERSHIP_POLL_INTERVAL) == 0)
    {
        char* end = NULL;
        const long value = strtol(child->content, &end, 10);
        if (!end || *end != '\0' || value <= 0)
        {
            mwarn("Invalid <%s> value '%s'; keeping %d seconds.",
                  CI_XML_OWNERSHIP_POLL_INTERVAL,
                  child->content,
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
    else if (strcmp(child->element, CI_XML_INSECURE_SKIP_TLS_VERIFY) == 0)
    {
        const int value = wm_container_instances_parse_bool(child->content);
        if (value < 0)
        {
            mwarn("Invalid <%s> value '%s'; expected yes/no.", CI_XML_INSECURE_SKIP_TLS_VERIFY, child->content);
        }
        else
        {
            config->kubernetes.insecure_skip_tls_verify = (unsigned int)value;
        }
    }
    else
    {
        mwarn("Unknown option '%s' in a <%s> block of type '%s'.",
              child->element,
              CI_XML_CONTAINER_INSTANCES,
              CI_XML_TYPE_KUBERNETES);
    }
}

static void wm_container_instances_parse_docker_option(xml_node* child, wm_container_instances_t* config)
{
    if (strcmp(child->element, CI_XML_SOCKET_PATH) == 0)
    {
        os_free(config->docker_socket_path);
        os_strdup(child->content, config->docker_socket_path);
    }
    else
    {
        mwarn("Unknown option '%s' in a <%s> block of type '%s'.",
              child->element,
              CI_XML_CONTAINER_INSTANCES,
              CI_XML_TYPE_DOCKER);
    }
}

/* One <container_instances> block. Two passes over its children: <type> and
 * <enabled> decide what the block IS, and only then can the remaining options
 * be routed to the right runtime -- they are siblings of <type>, so their
 * meaning is not known until it has been read, whatever order the operator
 * wrote them in. */
static int wm_container_instances_parse_block(const OS_XML* xml, xml_node* node, wm_container_instances_t* config)
{
    xml_node** children = OS_GetElementsbyNode(xml, node);

    if (!children)
    {
        wm_container_instances_invalidate(config, "an empty <container_instances> block has no <type>");
        return OS_INVALID;
    }

    const char* type = NULL;
    int block_enabled = 1; /* A block written at all is the opt-in; <enabled>no</enabled> opts back out. */

    for (int i = 0; children[i]; i++)
    {
        if (!children[i]->element || !children[i]->content)
        {
            continue;
        }
        if (strcmp(children[i]->element, CI_XML_TYPE) == 0)
        {
            type = children[i]->content;
        }
        else if (strcmp(children[i]->element, CI_XML_ENABLED) == 0)
        {
            const int value = wm_container_instances_parse_bool(children[i]->content);
            if (value < 0)
            {
                merror("Invalid <%s> value '%s' in <%s>.",
                       CI_XML_ENABLED,
                       children[i]->content,
                       CI_XML_CONTAINER_INSTANCES);
                OS_ClearNode(children);
                wm_container_instances_invalidate(config, "an <enabled> value is not yes/no");
                return OS_INVALID;
            }
            block_enabled = value;
        }
    }

    if (!type)
    {
        OS_ClearNode(children);
        wm_container_instances_invalidate(config, "a <container_instances> block is missing its <type>");
        return OS_INVALID;
    }

    const int is_kubernetes = (strcmp(type, CI_XML_TYPE_KUBERNETES) == 0);
    const int is_docker = (strcmp(type, CI_XML_TYPE_DOCKER) == 0);

    if (!is_kubernetes && !is_docker)
    {
        merror("Unknown <%s> value '%s'; expected '%s' or '%s'.",
               CI_XML_TYPE,
               type,
               CI_XML_TYPE_DOCKER,
               CI_XML_TYPE_KUBERNETES);
        OS_ClearNode(children);
        wm_container_instances_invalidate(config, "a <container_instances> block has an unknown <type>");
        return OS_INVALID;
    }

    /* One source per runtime. A second block of the same type would be the
     * multi-socket topology, which #37382 descoped: two sources sharing a type
     * have no way to be told apart downstream. */
    if ((is_kubernetes && config->kubernetes_present) || (is_docker && config->docker_present))
    {
        merror("Duplicate <%s> block of type '%s'.", CI_XML_CONTAINER_INSTANCES, type);
        OS_ClearNode(children);
        wm_container_instances_invalidate(config, "two <container_instances> blocks share a <type>");
        return OS_INVALID;
    }

    if (!block_enabled)
    {
        /* Parsed and validated, then deliberately not registered: the operator
         * asked for this runtime to be off, and a disabled block must not
         * become an enrichment source. */
        minfo("<%s> block of type '%s' is disabled.", CI_XML_CONTAINER_INSTANCES, type);
        OS_ClearNode(children);
        return 0;
    }

    for (int i = 0; children[i]; i++)
    {
        if (!children[i]->element || !children[i]->content)
        {
            continue;
        }
        if (strcmp(children[i]->element, CI_XML_TYPE) == 0 || strcmp(children[i]->element, CI_XML_ENABLED) == 0)
        {
            continue; /* Consumed by the pass above. */
        }
        if (is_kubernetes)
        {
            wm_container_instances_parse_kubernetes_option(children[i], config);
        }
        else
        {
            wm_container_instances_parse_docker_option(children[i], config);
        }
    }

    if (is_kubernetes)
    {
        config->kubernetes_present = 1;
    }
    else
    {
        config->docker_present = 1;
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
        if (strcmp(nodes[i]->element, CI_XML_CONTAINER_INSTANCES) == 0)
        {
            if (wm_container_instances_parse_block(xml, nodes[i], config) < 0)
            {
                return 0; /* Already invalidated and reported; fail closed, not fatal. */
            }
        }
        else if (strcmp(nodes[i]->element, CI_XML_SYSCHECK) == 0)
        {
            /* syscheckd reads this one; warning here would fire on every correct
             * configuration. */
            continue;
        }
        else if (strcmp(nodes[i]->element, CI_XML_SYSCOLLECTOR) == 0)
        {
            /* Handled by Read_ContainerSecurity, which holds the module list this
             * block has to reach. */
            continue;
        }
        else
        {
            mwarn("Unknown option '%s' in <container_security>.", nodes[i]->element);
        }
    }

    /* Each registered block is one enrichment source; both types enable
     * dual-runtime monitoring. */
    if (!config->kubernetes_present && !config->docker_present)
    {
        if (!config->invalid)
        {
            wm_container_instances_invalidate(
                config, "no enabled <container_instances> block of type 'docker' or 'kubernetes' was found");
        }
        return 0;
    }

    config->enabled = 1;

    if (config->kubernetes_present)
    {
        if (!config->kubernetes.kubeconfig)
        {
            os_strdup(WM_CONTAINER_INSTANCES_DEF_KUBECONFIG, config->kubernetes.kubeconfig);
        }
        if (!config->kubernetes.node_name)
        {
            os_strdup(WM_CONTAINER_INSTANCES_DEF_NODE_NAME, config->kubernetes.node_name);
        }
    }

    return 0;
}

/* <syscollector> under <container_security> configures the container inventory pass
 * and nothing else: <enabled> is flags.container_baseline and <interval> is
 * container_baseline_interval. Host inventory cadence stays in <wodle name="syscollector">,
 * so no setting in this section can change what the host scan does.
 *
 * The module is reached through wm_syscollector_get_or_create() rather than allocated
 * here, so this block and the top-level wodle can appear in either order without one of
 * them skipping the defaults. */
static int wm_container_security_parse_syscollector(const OS_XML* xml, xml_node* node, wmodule** wmodules)
{
    wm_sys_t* syscollector = wm_syscollector_get_or_create(wmodules);

    /* Writing the block is the opt-in, matching <container_instances>. */
    syscollector->flags.container_baseline = 1;

    xml_node** children = OS_GetElementsbyNode(xml, node);

    if (!children)
    {
        return 0;
    }

    for (int i = 0; children[i]; i++)
    {
        if (!children[i]->element)
        {
            continue;
        }

        if (strcmp(children[i]->element, CI_XML_ENABLED) == 0)
        {
            const int enabled = wm_container_instances_parse_bool(children[i]->content);

            if (enabled < 0)
            {
                merror("Invalid <%s> value '%s' in <container_security><%s>. Container inventory disabled.",
                       CI_XML_ENABLED,
                       children[i]->content ? children[i]->content : "",
                       CI_XML_SYSCOLLECTOR);
                syscollector->flags.container_baseline = 0;
                break;
            }

            syscollector->flags.container_baseline = (unsigned int)enabled;
        }
        else if (strcmp(children[i]->element, CI_XML_INTERVAL) == 0)
        {
            unsigned int parsed = 0;

            if (wm_syscollector_parse_interval(children[i]->content, &parsed) != 0)
            {
                merror("Invalid <%s> value '%s' in <container_security><%s>. Container inventory disabled.",
                       CI_XML_INTERVAL,
                       children[i]->content ? children[i]->content : "",
                       CI_XML_SYSCOLLECTOR);
                syscollector->flags.container_baseline = 0;
                break;
            }

            /* 0 is accepted and meaningful: follow the host <interval>. */
            syscollector->container_baseline_interval = parsed;
        }
        else
        {
            mwarn("Unknown option '%s' in <container_security><%s>.", children[i]->element, CI_XML_SYSCOLLECTOR);
        }
    }

    OS_ClearNode(children);
    return 0;
}

int Read_ContainerSecurity(const OS_XML* xml, xml_node* node, void* d1)
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

    if (result == 0 && children)
    {
        for (int i = 0; children[i]; i++)
        {
            if (children[i]->element && strcmp(children[i]->element, CI_XML_SYSCOLLECTOR) == 0)
            {
                wm_container_security_parse_syscollector(xml, children[i], wmodules);
            }
        }
    }

    OS_ClearNode(children);
    return result;
}

#endif /* __linux__ && CLIENT */
