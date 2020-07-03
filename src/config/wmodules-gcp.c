/* Copyright (C) 2015-2019, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#ifndef WIN32

#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_gcp.h"

static const char *XML_ENABLED = "enabled";
static const char *XML_PROJECT_ID = "project_id";
static const char *XML_SUBSCRIPTION_NAME = "subscription_name";
static const char *XML_CREDENTIALS_FILE = "credentials_file";
static const char *XML_MAX_MESSAGES = "max_messages";
static const char *XML_PULL_ON_START = "pull_on_start";
static const char *XML_LOGGING = "logging";

static short eval_bool(const char *str) {
    return !str ? OS_INVALID : !strcmp(str, "yes") ? 1 : !strcmp(str, "no") ? 0 : OS_INVALID;
}

/* Read XML configuration */

int wm_gcp_read(xml_node **nodes, wmodule *module) {
    unsigned int i;
    wm_gcp *gcp;

    if (!module->data) {
        os_calloc(1, sizeof(wm_gcp), gcp);
        gcp->enabled = 1;
        gcp->max_messages = 100;
        gcp->project_id = NULL;
        sched_scan_init(&(gcp->scan_config));
        gcp->scan_config.interval = WM_GCP_DEF_INTERVAL;
        gcp->subscription_name = NULL;
        gcp->credentials_file = NULL;
        gcp->pull_on_start = 1;
        gcp->logging = 2;
        module->context = &WM_GCP_CONTEXT;
        module->tag = strdup(module->context->name);
        module->data = gcp;
    }

    gcp = module->data;

    if (!nodes) {
        mwarn("Empty configuration at module '%s'.", WM_GCP_CONTEXT.name);
        return OS_INVALID;
    }

    for (i = 0; nodes[i]; i++) {
        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        }
        else if (!strcmp(nodes[i]->element, XML_ENABLED)) {
            int enabled = eval_bool(nodes[i]->content);

            if(enabled == OS_INVALID){
                merror("Invalid content for tag '%s'", XML_ENABLED);
                return OS_INVALID;
            }

            gcp->enabled = enabled;
        }
        else if (!strcmp(nodes[i]->element, XML_PROJECT_ID)) {
            if (strlen(nodes[i]->content) == 0) {
                merror("Empty content for tag '%s' at module '%s'", XML_PROJECT_ID, WM_GCP_CONTEXT.name);
                return OS_INVALID;
            }
            os_strdup(nodes[i]->content, gcp->project_id);
        }
        else if (!strcmp(nodes[i]->element, XML_SUBSCRIPTION_NAME)) {
            if (strlen(nodes[i]->content) == 0) {
                merror("Empty content for tag '%s' at module '%s'", XML_SUBSCRIPTION_NAME, WM_GCP_CONTEXT.name);
                return OS_INVALID;
            }
            os_strdup(nodes[i]->content, gcp->subscription_name);
        }
        else if (!strcmp(nodes[i]->element, XML_CREDENTIALS_FILE)) {
            if(strlen(nodes[i]->content) >= PATH_MAX) {
                merror("File path is too long. Max path length is %d.", PATH_MAX);
                return OS_INVALID;
            } else if (strlen(nodes[i]->content) == 0) {
                merror("Empty content for tag '%s' at module '%s'", XML_CREDENTIALS_FILE, WM_GCP_CONTEXT.name);
                return OS_INVALID;
            }

            char realpath_buffer[PATH_MAX] = {0};

            if(nodes[i]->content[0] == '/') {
                sprintf(realpath_buffer, "%s", nodes[i]->content);
            } else {
                char relative_path[PATH_MAX] = {0};

                sprintf(relative_path, "%s/", DEFAULTDIR);
                strcat(relative_path, nodes[i]->content);
                const char * const realpath_buffer_ref = realpath(relative_path, realpath_buffer);
                if (!realpath_buffer_ref) {
                    mwarn("File '%s' from tag '%s' not found.", realpath_buffer, XML_CREDENTIALS_FILE);
                    return OS_INVALID;
                }
            }

            // Beware of IsFile inverted, twisted logic.
            if (IsFile(realpath_buffer)) {
                mwarn("File '%s' not found. Check your configuration.", realpath_buffer);
                return OS_INVALID;
            }

            os_strdup(realpath_buffer, gcp->credentials_file);
        }
        else if (!strcmp(nodes[i]->element, XML_MAX_MESSAGES)) {
            if (strlen(nodes[i]->content) == 0) {
                merror("Empty content for tag '%s'", XML_MAX_MESSAGES);
                return OS_INVALID;
            }

            unsigned int j;
            for(j=0; j < strlen(nodes[i]->content); j++) {
                if (!isdigit(nodes[i]->content[j])) {
                    merror("Tag '%s' from the '%s' module should not have an alphabetic character.", XML_MAX_MESSAGES, WM_GCP_CONTEXT.name);
                    return OS_INVALID;
                }
            }

            char *endptr;
            gcp->max_messages = strtoul(nodes[i]->content, &endptr, 0);
        }
        else if (!strcmp(nodes[i]->element, XML_PULL_ON_START)) {
            int pull_on_start = eval_bool(nodes[i]->content);

            if(pull_on_start == OS_INVALID){
                merror("Invalid content for tag '%s'", XML_PULL_ON_START);
                return OS_INVALID;
            }

            gcp->pull_on_start = pull_on_start;
        }
        else if (!strcmp(nodes[i]->element, XML_LOGGING)) {
            if (!strcmp(nodes[i]->content, "disabled")) {
                gcp->logging = 0;
            } else if (!strcmp(nodes[i]->content, "debug")) {
                gcp->logging = 1;
            } else if (!strcmp(nodes[i]->content, "info")) {
                gcp->logging = 2;
            } else if (!strcmp(nodes[i]->content, "warning")) {
                gcp->logging = 3;
            } else if (!strcmp(nodes[i]->content, "error")) {
                gcp->logging = 4;
            } else if (!strcmp(nodes[i]->content, "critical")) {
                gcp->logging = 5;
            } else if (strlen(nodes[i]->content) == 0) {
                merror("Empty content for tag '%s'", XML_LOGGING);
                return OS_INVALID;
            } else {
                merror("Invalid content for tag '%s'", XML_LOGGING);
                return OS_INVALID;
            }
        } 
        else if (is_sched_tag(nodes[i]->element)) {
            // Do nothing
        } else {
            merror("No such tag '%s' at module '%s'.", nodes[i]->element, WM_GCP_CONTEXT.name);	
            return OS_INVALID;
        }
        
    }

    const int sched_read = sched_scan_read(&(gcp->scan_config), nodes, module->context->name);
    if ( sched_read != 0 ) {
        return OS_INVALID;
    }

    if (!gcp->project_id) {
        merror("No value defined for tag '%s' in module '%s'", XML_PROJECT_ID, WM_GCP_CONTEXT.name);
        return OS_INVALID;
    }

    if (!gcp->subscription_name) {
        merror("No value defined for tag '%s' in module '%s'", XML_SUBSCRIPTION_NAME, WM_GCP_CONTEXT.name);
        return OS_INVALID;
    }

    if (!gcp->credentials_file) {
        merror("No value defined for tag '%s' in module '%s'", XML_CREDENTIALS_FILE, WM_GCP_CONTEXT.name);
        return OS_INVALID;
    }

    return 0;
}
#endif /* WIN32 */
