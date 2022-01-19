/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/
#ifndef WIN32

#include "wazuh_modules/wmodules.h"
#include <stdio.h>
#define MAX_TIMEOUT_VALUE 9000

static const char *XML_ENABLED = "enabled";
static const char *XML_TAG = "tag";
static const char *XML_OBJECT_KEY = "object_key";
static const char *XML_SOCKET_PATH = "socket_path";
static const char *XML_ADDRESS = "address";
static const char *XML_PORT = "port";
static const char *XML_SHARED_KEY = "shared_key";
static const char *XML_CA_FILE= "ca_file";
static const char *XML_USER = "user";
static const char *XML_PASSWORD = "password";
static const char *XML_TIMEOUT = "timeout";
static const char *XML_POLL_INTERVAL = "poll_interval";
static const char *XML_KEEPALIVE = "keepalive";
static const char *XML_COUNT = "count";
static const char *XML_IDLE = "idle";
static const char *XML_INTERVAL = "interval";

static short eval_bool(const char *str)
{
    return !str ? OS_INVALID : !strcmp(str, "yes") ? 1 : !strcmp(str, "no") ? 0 : OS_INVALID;
}

static void wm_fluent_parse_keepalive(xml_node * keepalive, XML_NODE children, wm_fluent_t *fluent) {
    int i;
    fluent->keepalive.enabled = true;

    // Parse attribute

    for (i = 0; keepalive->attributes && keepalive->attributes[i] && keepalive->values[i]; i++) {
        if (strcmp(keepalive->attributes[i], XML_ENABLED) == 0) {
            short value = eval_bool(keepalive->values[i]);

            if (value != OS_INVALID) {
                fluent->keepalive.enabled = value;
            } else {
                mwarn("Invalid value '%s' for attribute '%s' at module '%s'", keepalive->values[i], keepalive->attributes[i], WM_FLUENT_CONTEXT.name);
            }
        } else {
            mwarn("Unknown attribute '%s' at module '%s'", keepalive->attributes[i], WM_FLUENT_CONTEXT.name);
        }
    }

    // Parse suboptions

    for (i = 0; children && children[i]; i++) {
        if (strcmp(children[i]->element, XML_COUNT) == 0) {
            char * end;
            int value = strtol(children[i]->content, &end, 10);

            if (*end == '\0' && value > 0 && value < 32768) {
                fluent->keepalive.count = value;
            } else {
                mwarn("Invalid value '%s' for option '%s' at module '%s", children[i]->content, children[i]->element, WM_FLUENT_CONTEXT.name);
            }
        } else if (strcmp(children[i]->element, XML_IDLE) == 0) {
            char * end;
            int value = strtol(children[i]->content, &end, 10);

            if (*end == '\0' && value > 0 && value < 32768) {
                fluent->keepalive.idle = value;
            } else {
                mwarn("Invalid value '%s' for option '%s' at module '%s", children[i]->content, children[i]->element, WM_FLUENT_CONTEXT.name);
            }
        } else if (strcmp(children[i]->element, XML_INTERVAL) == 0) {
            char * end;
            int value = strtol(children[i]->content, &end, 10);

            if (*end == '\0' && value > 0 && value < 32768) {
                fluent->keepalive.interval = value;
            } else {
                mwarn("Invalid value '%s' for option '%s' at module '%s", children[i]->content, children[i]->element, WM_FLUENT_CONTEXT.name);
            }
        } else {
            mwarn("Unknown option '%s' at module '%s", children[i]->element, WM_FLUENT_CONTEXT.name);
        }
    }
}

// Reading function
int wm_fluent_read(const OS_XML *xml, xml_node **nodes, wmodule *module)
{
    unsigned int i;
    wm_fluent_t *fluent;

    if(!module->data) {
        os_calloc(1, sizeof(wm_fluent_t), fluent);
        fluent->enabled = 1;
        fluent->tag = NULL;
        fluent->sock_path = NULL;
        fluent->address = strdup("localhost");
        fluent->port = 24224;
        fluent->shared_key = NULL;
        fluent->certificate = NULL;
        fluent->user_name = NULL;
        fluent->user_pass = NULL;
        fluent->poll_interval = 60;
        module->context = &WM_FLUENT_CONTEXT;
        module->tag = strdup(module->context->name);
        module->data = fluent;
    }

    fluent = module->data;

    if (!nodes)
        return 0;

    for(i = 0; nodes[i]; i++)
    {
        if(!nodes[i]->element)
        {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        }
        else if (!strcmp(nodes[i]->element, XML_ENABLED))
        {
            int enabled = eval_bool(nodes[i]->content);

            if(enabled == OS_INVALID){
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_FLUENT_CONTEXT.name);
                return OS_INVALID;
            } else {
                fluent->enabled = enabled;
            }
        }
        else if (!strcmp(nodes[i]->element, XML_TAG))
        {
            if(strlen(nodes[i]->content) >= OS_MAXSTR) {
                merror("Tag is too long at module '%s'. Max tag length is %d", WM_FLUENT_CONTEXT.name,PATH_MAX);
                return OS_INVALID;
            } else if (strlen(nodes[i]->content) == 0) {
                merror("Empty tag value at '%s'.", WM_FLUENT_CONTEXT.name);
                return OS_INVALID;
            }

            free(fluent->tag);
            os_strdup(nodes[i]->content,fluent->tag);
        }
        else if (!strcmp(nodes[i]->element, XML_OBJECT_KEY))
        {
            if (strlen(nodes[i]->content) == 0) {
                mwarn("Empty value for option <%s> at %s.", nodes[i]->element, WM_FLUENT_CONTEXT.name);
            } else {
                free(fluent->object_key);
                os_strdup(nodes[i]->content, fluent->object_key);
            }
        }
        else if (!strcmp(nodes[i]->element, XML_SOCKET_PATH))
        {
            if(strlen(nodes[i]->content) >= PATH_MAX) {
                merror("Socket path is too long at module '%s'. Max socket path length is %d", WM_FLUENT_CONTEXT.name,PATH_MAX);
                return OS_INVALID;
            } else if (strlen(nodes[i]->content) == 0) {
                merror("Empty tag value at '%s'.", WM_FLUENT_CONTEXT.name);
                return OS_INVALID;
            }

            free(fluent->sock_path);
            os_strdup(nodes[i]->content,fluent->sock_path);
        }
        else if (!strcmp(nodes[i]->element, XML_ADDRESS))
        {
            if(strlen(nodes[i]->content) >= OS_MAXSTR) {
                merror("Address is too long at module '%s'. Max address length is %d", WM_FLUENT_CONTEXT.name,PATH_MAX);
                return OS_INVALID;
            } else if (strlen(nodes[i]->content) == 0) {
                merror("Empty tag value at '%s'.", WM_FLUENT_CONTEXT.name);
                return OS_INVALID;
            }

            free(fluent->address);
            os_strdup(nodes[i]->content,fluent->address);
        }
        else if (!strcmp(nodes[i]->element, XML_PORT))
        {
            if (!OS_StrIsNum(nodes[i]->content)) {
                merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                return (OS_INVALID);
            } else {
                fluent->port = atoi(nodes[i]->content);
                if (fluent->port < 1 || fluent->port > 65534) {
                    merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                    return (OS_INVALID);
                }
            }
        }
        else if (!strcmp(nodes[i]->element, XML_SHARED_KEY))
        {
            if(strlen(nodes[i]->content) >= OS_MAXSTR) {
                merror("Shared key is too long at module '%s'. Max shared key length is %d", WM_FLUENT_CONTEXT.name,PATH_MAX);
                return OS_INVALID;
            } else if (strlen(nodes[i]->content) == 0) {
                merror("Empty shared key value at '%s'.", WM_FLUENT_CONTEXT.name);
                return OS_INVALID;
            }

            free(fluent->shared_key);
            os_strdup(nodes[i]->content,fluent->shared_key);
        }
        else if (!strcmp(nodes[i]->element, XML_CA_FILE))
        {
            if(strlen(nodes[i]->content) >= PATH_MAX) {
                merror("CA file path is too long at module '%s'. Max CA file path length is %d", WM_FLUENT_CONTEXT.name,PATH_MAX);
                return OS_INVALID;
            } else if (strlen(nodes[i]->content) == 0) {
                merror("Empty CA file value at '%s'.", WM_FLUENT_CONTEXT.name);
                return OS_INVALID;
            }

            free(fluent->certificate);
            os_strdup(nodes[i]->content,fluent->certificate);
        }
        else if (!strcmp(nodes[i]->element, XML_USER))
        {
            if(strlen(nodes[i]->content) >= OS_MAXSTR) {
                merror("User is too long at module '%s'. Max user length is %d", WM_FLUENT_CONTEXT.name,PATH_MAX);
                return OS_INVALID;
            } else if (strlen(nodes[i]->content) == 0) {
                mwarn("Empty user value at '%s'.", WM_FLUENT_CONTEXT.name);
            }

            free(fluent->user_name);
            os_strdup(nodes[i]->content,fluent->user_name);
        }
        else if (!strcmp(nodes[i]->element, XML_PASSWORD))
        {
            if(strlen(nodes[i]->content) >= OS_MAXSTR) {
                merror("Password is too long at module '%s'. Max password length is %d", WM_FLUENT_CONTEXT.name,PATH_MAX);
                return OS_INVALID;
            } else if (strlen(nodes[i]->content) == 0) {
                mwarn("Empty pass value at '%s'.", WM_FLUENT_CONTEXT.name);
            }

            free(fluent->user_pass);
            os_strdup(nodes[i]->content,fluent->user_pass);
        }
        else if (!strcmp(nodes[i]->element, XML_TIMEOUT))
        {
            char *pt = nodes[i]->content;

            while (*pt != '\0') {
                if (!isdigit((int)*pt)) {
                    merror("Invalid timeout at module '%s'", WM_FLUENT_CONTEXT.name);
                    return OS_INVALID;
                }
                pt++;
            }

            fluent->timeout = atoi(nodes[i]->content);

            if (fluent->timeout < 0 || fluent->timeout > MAX_TIMEOUT_VALUE) {
                merror("Invalid timeout at module '%s'", WM_FLUENT_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_POLL_INTERVAL)) {
            char * end;
            int value = strtol(nodes[i]->content, &end, 10);

            if (*end == '\0' && value > 0 && value < 7200) {
                fluent->poll_interval = value;
            } else {
                mwarn("Invalid value '%s' for option '%s' at module '%s", nodes[i]->content, nodes[i]->element, WM_FLUENT_CONTEXT.name);
            }
        } else if (strcmp(nodes[i]->element, XML_KEEPALIVE) == 0) {
            XML_NODE children = OS_GetElementsbyNode(xml, nodes[i]);
            wm_fluent_parse_keepalive(nodes[i], children, fluent);
            OS_ClearNode(children);
        }
        else
        {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_FLUENT_CONTEXT.name);
        }
    }

    if (!fluent->user_name) {
        os_strdup("", fluent->user_name);
    }

    if (!fluent->user_pass) {
        os_strdup("", fluent->user_pass);
    }

    if (!fluent->object_key) {
        os_strdup("message", fluent->object_key);
    }

    return 0;
}
#endif
