/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "wazuh_modules/wmodules.h"
#include <stdio.h>

static const char *XML_DISABLED = "disabled";
static const char *XML_BINPATH = "bin_path";
static const char *XML_LOGPATH = "log_path";
static const char *XML_CONFIGPATH = "config_path";
static const char *XML_PACK = "pack";
static const char *XML_PACKNAME = "name";
static const char *XML_ADD_LABELS = "add_labels";
static const char *XML_RUN_DAEMON = "run_daemon";

static short eval_bool(const char *str)
{
    return !str ? OS_INVALID : !strcmp(str, "yes") ? 1 : !strcmp(str, "no") ? 0 : OS_INVALID;
}

// Reading function
int wm_osquery_monitor_read(xml_node **nodes, wmodule *module)
{
    unsigned int i;
    unsigned int pack_i = 0;
    wm_osquery_monitor_t *osquery_monitor;

    os_calloc(1, sizeof(wm_osquery_monitor_t), osquery_monitor);
    os_calloc(1, sizeof(wm_osquery_pack_t *), osquery_monitor->packs);
    osquery_monitor->disable = 0;
    osquery_monitor->run_daemon = 1;
    module->context = &WM_OSQUERYMONITOR_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = osquery_monitor;

#ifdef WIN32
    os_strdup("C:\\Program Files\\osquery\\osqueryd", osquery_monitor->bin_path);
    os_strdup("C:\\Program Files\\osquery\\log\\osqueryd.results.log", osquery_monitor->log_path);
    os_strdup("C:\\Program Files\\osquery\\osquery.conf", osquery_monitor->config_path);

#else
    os_strdup("/var/log/osquery/osqueryd.results.log", osquery_monitor->log_path);
    os_strdup("/etc/osquery/osquery.conf", osquery_monitor->config_path);
#endif

    if (!nodes)
        return 0;

    for(i = 0; nodes[i]; i++)
    {
        if(!nodes[i]->element)
        {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        }
        else if (!strcmp(nodes[i]->element, XML_DISABLED))
        {
            if (osquery_monitor->disable = eval_bool(nodes[i]->content), osquery_monitor->disable == OS_INVALID) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_DISABLED, WM_OSQUERYMONITOR_CONTEXT.name);
                return OS_INVALID;
            }
        }
        else if(!strcmp(nodes[i]->element, XML_BINPATH))
        {
#ifdef WIN32
            if (is_network_path(nodes[i]->content)) {
                mwarn(NETWORK_PATH_CONFIGURED, nodes[i]->element, nodes[i]->content);
                continue;
            }
#endif
            free(osquery_monitor->bin_path);
            osquery_monitor->bin_path = strdup(nodes[i]->content);
        }
        else if(!strcmp(nodes[i]->element, XML_LOGPATH))
        {
#ifdef WIN32
            if (is_network_path(nodes[i]->content)) {
                mwarn(NETWORK_PATH_CONFIGURED, nodes[i]->element, nodes[i]->content);
                continue;
            }
#endif
            free(osquery_monitor->log_path);
            osquery_monitor->log_path = strdup(nodes[i]->content);
            mdebug2("Logpath read: %s", osquery_monitor->log_path);
        }
        else if(!strcmp(nodes[i]->element, XML_CONFIGPATH))
        {
#ifdef WIN32
            if (is_network_path(nodes[i]->content)) {
                mwarn(NETWORK_PATH_CONFIGURED, nodes[i]->element, nodes[i]->content);
                continue;
            }
#endif
            free(osquery_monitor->config_path);
            osquery_monitor->config_path = strdup(nodes[i]->content);
            mdebug2("configPath read: %s", osquery_monitor->config_path);
        } else if (!strcmp(nodes[i]->element, XML_PACK)) {
            wm_osquery_pack_t * pack;

            if (!(nodes[i]->attributes && *nodes[i]->attributes)) {
                return OS_INVALID;
            } else if (strcmp(*nodes[i]->attributes, XML_PACKNAME)) {
                merror("No such attribute '%s' in osquery element <%s>", *nodes[i]->attributes, XML_PACK);
                return OS_INVALID;
            }

            os_malloc(sizeof(wm_osquery_pack_t), pack);
            os_strdup(*nodes[i]->values, pack->name);
            os_strdup(nodes[i]->content, pack->path);
            os_realloc(osquery_monitor->packs, (pack_i + 2) * sizeof(wm_osquery_pack_t *), osquery_monitor->packs);
            osquery_monitor->packs[pack_i] = pack;
            osquery_monitor->packs[++pack_i] = NULL;
        } else if (!strcmp(nodes[i]->element, XML_ADD_LABELS)) {
            if (osquery_monitor->add_labels = eval_bool(nodes[i]->content), osquery_monitor->add_labels == OS_INVALID) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_ADD_LABELS, WM_OSQUERYMONITOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_RUN_DAEMON)) {
            if (osquery_monitor->run_daemon = eval_bool(nodes[i]->content), osquery_monitor->run_daemon == OS_INVALID) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_RUN_DAEMON, WM_OSQUERYMONITOR_CONTEXT.name);
                return OS_INVALID;
            }
        } else {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_OSQUERYMONITOR_CONTEXT.name);
        }

    }
    return 0;
}
